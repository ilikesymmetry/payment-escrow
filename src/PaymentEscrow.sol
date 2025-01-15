// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";
import {SpendPermissionManager} from "spend-permissions/SpendPermissionManager.sol";

/// @notice Route and escrow payments using Spend Permissions (https://github.com/coinbase/spend-permissions).
contract PaymentEscrow {
    /// @notice ERC-7528 native token address
    address public constant NATIVE_TOKEN = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    SpendPermissionManager public immutable PERMISSION_MANAGER;

    /// @notice Amount of tokens escrowed for a specific Spend Permission.
    ///
    /// @dev Used to limit amount that can be captured or refunded from escrow.
    mapping(bytes32 permissionHash => uint256 value) internal _escrowed;

    /// @notice Amount of tokens captured for a specific Spend Permission.
    ///
    /// @dev Used to limit amount that can be refunded post-capture.
    mapping(bytes32 permissionhash => uint256 value) internal _captured;

    /// @notice Amount of tokens indebted by a merchant to an operator.
    ///
    /// @dev Used to limit amount that can be repaid.
    mapping(address operator => mapping(address merchant => mapping(address token => uint256 value))) internal _debt;

    mapping(address operator => uint16 bps) _feeBps;
    mapping(address operator => address recipient) _feeRecipient;

    /// @notice Payment was authorized, increasing value escrowed.
    ///
    /// @param permissionHash Hash of the SpendPermission used for payment.
    /// @param value Amount of tokens.
    event PaymentAuthorized(bytes32 indexed permissionHash, uint256 value);

    /// @notice Payment was captured, descreasing value escrowed.
    ///
    /// @param permissionHash Hash of the SpendPermission used for payment.
    /// @param value Amount of tokens.
    event PaymentCaptured(bytes32 indexed permissionHash, uint256 value);

    /// @notice Payment was refunded to buyer.
    ///
    /// @param permissionHash Hash of the SpendPermission used for payment.
    /// @param value Amount of tokens.
    event PaymentRefunded(bytes32 indexed permissionHash, uint256 value);

    /// @notice Debt extended to merchant.
    ///
    /// @param operator Operator to repay debt to.
    /// @param merchant Merchant indebted to operator.
    /// @param token Token to repay debt in.
    /// @param value Amount of debt to repay.
    event DebtExtended(address indexed operator, address indexed merchant, address token, uint256 value);

    /// @notice Debt settled, whether through repayment, cancellation, or other means.
    ///
    /// @param operator Operator to repay debt to.
    /// @param merchant Merchant indebted to operator.
    /// @param token Token to repay debt in.
    /// @param value Amount of debt repaid.
    event DebtSettled(address indexed operator, address indexed merchant, address token, uint256 value);

    event FeesUpdated(address indexed operator, uint16 feeBps, address feeRecipient);

    error InsufficientEscrow(bytes32 permissionHash, uint256 escrowedValue, uint160 requestedValue);
    error PermissionApprovalFailed();
    error InvalidSender(address sender, address expected);
    error InvalidRefunder(address sender, address merchant, address operator);
    error RefundExceedsCapture(uint256 refund, uint256 captured);
    error NativeTokenValueMismatch(uint256 msgValue, uint256 argValue);
    error RepaymentExceedsDebt(uint256 repayment, uint256 debt);
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

    /// @notice Move funds from buyer to escrow via spend permission.
    ///
    /// @dev Reverts if not called by operator.
    ///
    /// @param permission Spend Permission for this payment.
    /// @param value Amount of tokens to move.
    /// @param signature Signature from buyer or empty bytes.
    function authorize(
        SpendPermissionManager.SpendPermission calldata permission,
        uint160 value,
        bytes calldata signature
    ) external onlyOperator(permission) {
        // pull funds into this contract
        _preAuthorize(permission, signature);
        PERMISSION_MANAGER.spend(permission, value);

        // increase escrow
        bytes32 permissionHash = PERMISSION_MANAGER.getHash(permission);
        _escrowed[permissionHash] += value;
        emit PaymentAuthorized(permissionHash, value);
    }

    /// @notice Move funds from escrow to merchant.
    ///
    /// @dev Reverts if not called by operator.
    /// @dev Partial capture with custom value parameter and calling multiple times.
    ///
    /// @param permission Spend Permission for this payment.
    /// @param value Amount of tokens to move.
    function capture(SpendPermissionManager.SpendPermission calldata permission, uint160 value)
        external
        onlyOperator(permission)
    {
        (address merchant, address operator) = decodeExtraData(permission.extraData);
        bytes32 permissionHash = PERMISSION_MANAGER.getHash(permission);

        // check sufficient escrow to capture
        uint256 escrowedValue = _escrowed[permissionHash];
        if (escrowedValue < value) revert InsufficientEscrow(permissionHash, escrowedValue, value);

        // update state
        _escrowed[permissionHash] -= value;
        _captured[permissionHash] += value;

        // calculate fees and remaining payment value
        uint16 feeBps = _feeBps[operator];
        uint160 feeAmount = feeBps * value / 10_000;
        value -= feeAmount;

        // repay debt if any exists
        uint256 debt = _debt[operator][merchant][permission.token];
        if (debt > value) {
            // more debt than this payment can cover, repay debt and set payment value to zero
            _debt[operator][merchant][permission.token] = debt - value;
            value = 0;
            emit DebtSettled(operator, merchant, permission.token, value);
            _transfer(permission.token, operator, value);
        } else if (debt != 0) {
            // non-zero debt, but coverable with remainder of current capture value
            value -= uint160(debt);
            delete _debt[operator][merchant][permission.token];
            emit DebtSettled(operator, merchant, permission.token, debt);
            _transfer(permission.token, operator, debt);
        }

        // transfer fee
        if (feeAmount > 0) {
            _transfer(permission.token, _feeRecipient[operator], feeAmount);
        }

        // transfer payment if leftover
        if (value > 0) {
            emit PaymentCaptured(permissionHash, value);
            _transfer(permission.token, merchant, value);
        }
    }

    /// @notice Cancel payment by revoking permission and returning escrowed funds.
    ///
    /// @param permission Spend Permission for this payment.
    function void(SpendPermissionManager.SpendPermission calldata permission) external onlyOperator(permission) {
        PERMISSION_MANAGER.revokeAsSpender(permission);

        bytes32 permissionHash = PERMISSION_MANAGER.getHash(permission);
        uint256 escrowedValue = _escrowed[permissionHash];
        if (escrowedValue == 0) return;

        delete _escrowed[permissionHash];
        _transfer(permission.token, permission.account, escrowedValue);
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
    ///
    /// @dev Reverts if not called by merchant.
    ///
    /// @param permission Spend Permission for this payment.
    /// @param value Amount of tokens to move.
    function refund(SpendPermissionManager.SpendPermission calldata permission, uint160 value) external payable {
        // check sender is merchant
        (address merchant,) = decodeExtraData(permission.extraData);
        if (msg.sender != merchant) revert InvalidSender(msg.sender, merchant);

        _refund(permission, value, merchant);
    }

    /// @notice Move funds from escrow to buyer.
    ///
    /// @dev Reverts if not called by operator.
    ///
    /// @param permission Spend Permission for this payment.
    /// @param value Amount of tokens to move.
    function refundFromEscrow(SpendPermissionManager.SpendPermission calldata permission, uint160 value)
        external
        onlyOperator(permission)
    {
        bytes32 permissionHash = PERMISSION_MANAGER.getHash(permission);
        uint256 escrowedValue = _escrowed[permissionHash];
        if (escrowedValue < value) revert InsufficientEscrow(permissionHash, escrowedValue, value);

        _escrowed[permissionHash] -= value;
        _transfer(permission.token, permission.account, value);
    }

    /// @notice Return previously-captured tokens to buyer as an operator.
    ///
    /// @dev Reverts if not called by operator.
    /// @dev Merchant is indebted to the operator.
    ///
    /// @param permission Spend Permission for this payment.
    /// @param value Amount of tokens to move.
    function refundWithDebt(SpendPermissionManager.SpendPermission calldata permission, uint160 value)
        external
        payable
    {
        // check sender is operator
        (address merchant, address operator) = decodeExtraData(permission.extraData);
        if (msg.sender != operator) revert InvalidSender(msg.sender, operator);

        // increase merchant debt
        _debt[operator][merchant][permission.token] += value;
        emit DebtExtended(operator, merchant, permission.token, value);

        _refund(permission, value, operator);
    }

    /// @notice Partially repay the debt obligations of a calling merchant.
    ///
    /// @param operator Operator to repay debt to.
    /// @param token Token to repay debt in.
    /// @param value Amount of debt to repay.
    function repayDebt(address operator, address token, uint256 value) external payable {
        uint256 debt = _debt[operator][msg.sender][token];
        if (value > debt) revert RepaymentExceedsDebt(value, debt);

        _debt[operator][msg.sender][token] = debt - value;
        emit DebtSettled(operator, msg.sender, token, value);

        if (token == NATIVE_TOKEN) {
            if (msg.value != value) revert NativeTokenValueMismatch(msg.value, value);
            SafeTransferLib.safeTransferETH(operator, value);
        } else {
            SafeTransferLib.safeTransferFrom(token, msg.sender, operator, value);
        }
    }

    /// @notice Partially cancel the debt obligations of a merchant as an operator.
    ///
    /// @param merchant Merchant to cancel debt for.
    /// @param token Token used for debt.
    /// @param value Amount of debt to cancel.
    function cancelDebt(address merchant, address token, uint256 value) external {
        uint256 debt = _debt[msg.sender][merchant][token];
        if (value > debt) revert RepaymentExceedsDebt(value, debt);

        _debt[msg.sender][merchant][token] = debt - value;
        emit DebtSettled(msg.sender, merchant, token, value);
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

    /// @notice Approve a spend permission via signature and enforce its approval status.
    function _preAuthorize(SpendPermissionManager.SpendPermission calldata permission, bytes calldata signature)
        internal
    {
        bool approved = PERMISSION_MANAGER.approveWithSignature(permission, signature);
        if (!approved) revert PermissionApprovalFailed();
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
        emit PaymentRefunded(permissionHash, value);

        // return tokens to buyer
        if (permission.token == NATIVE_TOKEN) {
            if (value != msg.value) revert NativeTokenValueMismatch(msg.value, value);
            SafeTransferLib.safeTransferETH(permission.account, value);
        } else {
            SafeTransferLib.safeTransferFrom(permission.token, refunder, permission.account, value);
        }
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
