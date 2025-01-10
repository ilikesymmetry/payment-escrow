// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";
import {SpendPermissionManager} from "spend-permissions/SpendPermissionManager.sol";

/// @notice Route and escrow payments using Spend Permissions (https://github.com/coinbase/spend-permissions).
contract PaymentEscrow {
    address public constant NATIVE_TOKEN = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    SpendPermissionManager public immutable PERMISSION_MANAGER;

    mapping(bytes32 permissionHash => uint256 value) internal _escrowed;
    mapping(bytes32 permissionhash => uint256 value) internal _captured;
    mapping(address operator => mapping(address merchant => mapping(address token => uint256 value))) internal _debt;
    mapping(address operator => uint16 bps) _feeBps;
    mapping(address operator => address recipient) _feeRecipient;

    event PaymentEscrowed(bytes32 indexed permissionHash, uint256 value);
    event EscrowReduced(bytes32 indexed permissionHash, uint256 value);
    event PaymentCaptured(bytes32 indexed permissionHash, uint256 value);
    event PaymentRefunded(bytes32 indexed permissionHash, uint256 value);
    event DebtAdded(address indexed operator, address indexed merchant, address token, uint256 value);
    event DebtRepaid(address indexed operator, address indexed merchant, address token, uint256 value);
    event FeesUpdated(address indexed operator, uint16 feeBps, address feeRecipient);

    error InsufficientEscrow(bytes32 permissionHash, uint256 escrowedValue, uint160 requestedValue);
    error PermissionApprovalFailed();
    error InvalidSender(address sender, address expected);
    error InvalidRefunder(address sender, address merchant, address operator);
    error RefundExceedsCapture(uint256 refund, uint256 captured);
    error RefundValueMismatch(uint256 msgValue, uint256 argValue);
    error FeeBpsOverflow(uint16 feeBps);
    error ZeroFeeRecipient();

    modifier onlyOperator(SpendPermissionManager.SpendPermission calldata permission) {
        (, address operator) = decodeExtraData(permission.extraData);
        if (msg.sender != operator) revert InvalidSender(msg.sender, operator);
        _;
    }

    constructor(SpendPermissionManager spendPermissionManager) {
        PERMISSION_MANAGER = spendPermissionManager;
    }

    /// @notice Approve a spend permission via signature and enforce its approval status.
    function approve(SpendPermissionManager.SpendPermission calldata permission, bytes calldata signature) external {
        bool approved = PERMISSION_MANAGER.approveWithSignature(permission, signature);
        if (!approved) revert PermissionApprovalFailed();
    }

    /// @notice Move funds from buyer to escrow via pre-approved spend permission.
    function escrow(SpendPermissionManager.SpendPermission calldata permission, uint160 value)
        external
        onlyOperator(permission)
    {
        // pull funds into this contract
        PERMISSION_MANAGER.spend(permission, value);

        // increase escrow
        bytes32 permissionHash = PERMISSION_MANAGER.getHash(permission);
        _escrowed[permissionHash] += value;
        emit PaymentEscrowed(permissionHash, value);
    }

    /// @notice Move funds from escrow to buyer.
    /// @dev Intended for returning over-estimated taxes.
    function returnFromEscrow(SpendPermissionManager.SpendPermission calldata permission, uint160 value)
        external
        onlyOperator(permission)
    {
        bytes32 permissionHash = PERMISSION_MANAGER.getHash(permission);
        uint256 escrowedValue = _escrowed[permissionHash];
        if (escrowedValue < value) revert InsufficientEscrow(permissionHash, escrowedValue, value);

        _escrowed[permissionHash] -= value;
        emit EscrowReduced(permissionHash, escrowedValue);
        _transfer(permission.token, permission.account, value);
    }

    /// @notice Move funds from escrow to merchant.
    /// @dev Partial capture supported with custom value parameter.
    function captureFromEscrow(SpendPermissionManager.SpendPermission calldata permission, uint160 value)
        external
        onlyOperator(permission)
    {
        (address merchant, address operator) = decodeExtraData(permission.extraData);
        bytes32 permissionHash = PERMISSION_MANAGER.getHash(permission);

        // check sufficient escrow to capture
        uint256 escrowedValue = _escrowed[permissionHash];
        if (escrowedValue < value) revert InsufficientEscrow(permissionHash, escrowedValue, value);

        // decreate escrow
        _escrowed[permissionHash] -= value;
        emit EscrowReduced(permissionHash, value);

        _capture(permissionHash, operator, merchant, permission.token, value);
    }

    /// @notice Move funds from buyer to merchant using a pre-approved spend permission.
    function capture(SpendPermissionManager.SpendPermission calldata permission, uint160 value)
        external
        onlyOperator(permission)
    {
        // pull funds into this contract
        PERMISSION_MANAGER.spend(permission, value);

        bytes32 permissionHash = PERMISSION_MANAGER.getHash(permission);
        (address merchant, address operator) = decodeExtraData(permission.extraData);
        _capture(permissionHash, operator, merchant, permission.token, value);
    }

    /// @notice Return previously-captured tokens to buyer.
    /// @dev Callable by both merchant and operator. Calling operators are assumed to have a way to get paid back by merchants.
    function refundWithDebt(SpendPermissionManager.SpendPermission calldata permission, uint160 value)
        external
        payable
    {
        // check sender is operator
        (address merchant, address operator) = decodeExtraData(permission.extraData);
        if (msg.sender != operator) revert InvalidSender(msg.sender, operator);

        // increase merchant debt
        _debt[operator][merchant][permission.token] += value;
        emit DebtAdded(operator, merchant, permission.token, value);

        _refund(permission, value, operator);
    }

    /// @notice Return previously-captured tokens to buyer.
    /// @dev Only supports ERC20 tokens. Merchants should call `refund` directly for native token refunds.
    function refundFromMerchant(SpendPermissionManager.SpendPermission calldata permission, uint160 value) external {
        // check sender is operator
        (address merchant, address operator) = decodeExtraData(permission.extraData);
        if (msg.sender != operator) revert InvalidSender(msg.sender, operator);

        _refund(permission, value, merchant);
    }

    /// @notice Return previously-captured tokens to buyer.
    function refund(SpendPermissionManager.SpendPermission calldata permission, uint160 value) external payable {
        // check sender is merchant
        (address merchant,) = decodeExtraData(permission.extraData);
        if (msg.sender != merchant) revert InvalidSender(msg.sender, merchant);

        _refund(permission, value, merchant);
    }

    /// @notice Cancel payment by revoking permission and returning escrowed funds.
    function void(SpendPermissionManager.SpendPermission calldata permission) external onlyOperator(permission) {
        PERMISSION_MANAGER.revokeAsSpender(permission);

        bytes32 permissionHash = PERMISSION_MANAGER.getHash(permission);
        uint256 escrowedValue = _escrowed[permissionHash];
        if (escrowedValue == 0) return;

        delete _escrowed[permissionHash];
        emit EscrowReduced(permissionHash, escrowedValue);
        _transfer(permission.token, permission.account, escrowedValue);
    }

    /// @notice Partially cancel the debt obligations of a merchant as an operator.
    function cancelDebt(address merchant, address token, uint256 value) external {
        uint256 debt = _debt[msg.sender][merchant][token];
        if (value > debt) revert();

        _debt[msg.sender][merchant][token] = debt - value;
        emit DebtRepaid(msg.sender, merchant, token, value);
    }

    /// @notice Update fee take rate and recipient for operator.
    function updateFees(uint16 newFeeBps, address newFeeRecipient) external {
        if (newFeeBps > 10_000) revert FeeBpsOverflow(newFeeBps);
        if (newFeeRecipient == address(0)) revert ZeroFeeRecipient();

        _feeBps[msg.sender] = newFeeBps;
        _feeRecipient[msg.sender] = newFeeRecipient;
        emit FeesUpdated(msg.sender, newFeeBps, newFeeRecipient);
    }

    /// @notice Decode `SpendPermission.extraData` into a recipient and operator address.
    function decodeExtraData(bytes calldata extraData) public pure returns (address merchant, address operator) {
        return abi.decode(extraData, (address, address));
    }

    /// @notice Transfer funds to payment receipient from this contract.
    function _capture(bytes32 permissionHash, address operator, address merchant, address token, uint256 value)
        internal
    {
        _captured[permissionHash] += value;

        // calculate fees and remaining payment value
        uint16 feeBps = _feeBps[operator];
        uint256 feeAmount = feeBps * value / 10_000;
        value -= feeAmount;

        // repay debt if any exists
        uint256 debt = _debt[operator][merchant][token];
        if (debt >= value) {
            // more debt than this payment can cover, repay debt and set payment value to zero
            _debt[operator][merchant][token] = debt - value;
            value = 0;
            emit DebtRepaid(operator, merchant, token, value);
            _transfer(token, operator, value);
        } else if (debt != 0) {
            // non-zero debt, but coverable with remainder of current capture value
            value -= debt;
            delete _debt[operator][merchant][token];
            emit DebtRepaid(operator, merchant, token, debt);
            _transfer(token, operator, debt);
        }

        // transfer fee
        if (feeAmount > 0) {
            _transfer(token, _feeRecipient[operator], feeAmount);
        }

        // transfer payment if leftover
        if (value > 0) {
            emit PaymentCaptured(permissionHash, value);
            _transfer(token, merchant, value);
        }
    }

    /// @notice Return previously-captured tokens to buyer.
    function _refund(SpendPermissionManager.SpendPermission calldata permission, uint160 value, address refunder)
        internal
    {
        // limit refund value to previously captured
        bytes32 permissionHash = PERMISSION_MANAGER.getHash(permission);
        uint256 captured = _captured[permissionHash];
        if (captured < value) revert RefundExceedsCapture(value, captured);
        _captured[permissionHash] = captured - value;

        // return tokens to buyer
        if (permission.token == NATIVE_TOKEN) {
            if (value != msg.value) revert RefundValueMismatch(msg.value, value);
            SafeTransferLib.safeTransferETH(permission.account, value);
        } else {
            SafeTransferLib.safeTransferFrom(permission.token, refunder, permission.account, value);
        }

        emit PaymentRefunded(permissionHash, value);
    }

    /// @notice Transfer tokens from the escrow to a recipient.
    function _transfer(address token, address recipient, uint256 value) internal {
        if (token == NATIVE_TOKEN) {
            SafeTransferLib.safeTransferETH(recipient, value);
        } else {
            SafeTransferLib.safeTransfer(token, recipient, value);
        }
    }
}
