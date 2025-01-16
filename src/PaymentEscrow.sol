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
    /// @param refunder Entity sending tokens for refund.
    /// @param value Amount of tokens.
    event PaymentRefunded(bytes32 indexed permissionHash, address indexed refunder, uint256 value);

    error InsufficientEscrow(bytes32 permissionHash, uint256 escrowedValue, uint160 requestedValue);
    error PermissionApprovalFailed();
    error InvalidSender(address sender, address expected);
    error InvalidRefundSender(address sender, address operator, address merchant);
    error RefundExceedsCapture(uint256 refund, uint256 captured);
    error NativeTokenValueMismatch(uint256 msgValue, uint256 argValue);
    error FeeBpsOverflow(uint16 feeBps);
    error ZeroFeeRecipient();
    error ZeroValue();

    modifier onlyOperator(SpendPermissionManager.SpendPermission calldata permission) {
        (address operator,,,) = decodeExtraData(permission.extraData);
        if (msg.sender != operator) revert InvalidSender(msg.sender, operator);
        _;
    }

    modifier nonZeroValue(uint256 value) {
        if (value == 0) revert ZeroValue();
        _;
    }

    constructor(SpendPermissionManager spendPermissionManager) {
        PERMISSION_MANAGER = spendPermissionManager;
    }

    /// @notice Validates buyer signature and transfers funds from buyer to escrow.
    ///
    /// @dev Reverts if not called by operator.
    ///
    /// @param permission Spend Permission for this payment.
    /// @param value Amount of tokens to transfer.
    /// @param signature Signature from buyer or empty bytes.
    function authorize(
        SpendPermissionManager.SpendPermission calldata permission,
        uint160 value,
        bytes calldata signature
    ) external onlyOperator(permission) nonZeroValue(value) {
        bool approved = PERMISSION_MANAGER.approveWithSignature(permission, signature);
        if (!approved) revert PermissionApprovalFailed();

        _authorize(permission, value);
    }

    /// @notice Transfer funds from buyer to escrow via pre-approved SpendPermission.
    ///
    /// @dev Reverts if not called by operator.
    ///
    /// @param permission Spend Permission for this payment.
    /// @param value Amount of tokens to transfer.
    /// @param signature Signature from buyer or empty bytes.
    function reauthorize(SpendPermissionManager.SpendPermission calldata permission, uint160 value)
        external
        onlyOperator(permission)
        nonZeroValue(value)
    {
        _authorize(permission, value);
    }

    /// @notice Transfer previously-escrowed funds to merchant.
    ///
    /// @dev Reverts if not called by operator.
    /// @dev Partial capture with custom value parameter and calling multiple times.
    ///
    /// @param permission Spend Permission for this payment.
    /// @param value Amount of tokens to transfer.
    function capture(SpendPermissionManager.SpendPermission calldata permission, uint160 value)
        external
        onlyOperator(permission)
        nonZeroValue(value)
    {
        (address operator, address merchant, uint16 feeBps, address feeRecipient) =
            decodeExtraData(permission.extraData);
        bytes32 permissionHash = PERMISSION_MANAGER.getHash(permission);

        // check sufficient escrow to capture
        uint256 escrowedValue = _escrowed[permissionHash];
        if (escrowedValue < value) revert InsufficientEscrow(permissionHash, escrowedValue, value);

        // update state
        _escrowed[permissionHash] -= value;
        _captured[permissionHash] += value;
        emit PaymentCaptured(permissionHash, value);

        // calculate fees and remaining payment value
        uint160 feeAmount = feeBps * value / 10_000;
        value -= feeAmount;

        // transfer fee
        if (feeAmount > 0) _transfer(permission.token, feeRecipient, feeAmount);

        // transfer payment
        if (value > 0) _transfer(permission.token, merchant, value);
    }

    /// @notice Return previously-captured tokens to buyer.
    ///
    /// @dev Reverts if not called by operator or merchant.
    ///
    /// @param permission Spend Permission for this payment.
    /// @param value Amount of tokens to transfer.
    function refund(SpendPermissionManager.SpendPermission calldata permission, uint160 value)
        external
        payable
        nonZeroValue(value)
    {
        // check sender is operator or merchant
        (address operator, address merchant,,) = decodeExtraData(permission.extraData);
        if (msg.sender != operator && msg.sender != merchant) {
            revert InvalidRefundSender(msg.sender, operator, merchant);
        }

        // limit refund value to previously captured
        bytes32 permissionHash = PERMISSION_MANAGER.getHash(permission);
        uint256 captured = _captured[permissionHash];
        if (captured < value) revert RefundExceedsCapture(value, captured);

        _captured[permissionHash] = captured - value;
        emit PaymentRefunded(permissionHash, msg.sender, value);

        // return tokens to buyer
        if (permission.token == NATIVE_TOKEN) {
            if (value != msg.value) revert NativeTokenValueMismatch(msg.value, value);
            SafeTransferLib.safeTransferETH(permission.account, value);
        } else {
            SafeTransferLib.safeTransferFrom(permission.token, refunder, permission.account, value);
        }
    }

    /// @notice Return previously-escrowed funds to buyer.
    ///
    /// @dev Reverts if not called by operator or merchant.
    ///
    /// @param permission Spend Permission for this payment.
    /// @param value Amount of tokens to transfer.
    function refundFromEscrow(SpendPermissionManager.SpendPermission calldata permission, uint160 value)
        external
        nonZeroValue(value)
    {
        // check sender is operator or merchant
        (address operator, address merchant,,) = decodeExtraData(permission.extraData);
        if (msg.sender != operator && msg.sender != merchant) {
            revert InvalidRefundSender(msg.sender, operator, merchant);
        }

        bytes32 permissionHash = PERMISSION_MANAGER.getHash(permission);
        uint256 escrowedValue = _escrowed[permissionHash];
        if (escrowedValue < value) revert InsufficientEscrow(permissionHash, escrowedValue, value);

        _escrowed[permissionHash] -= value;
        emit PaymentRefunded(permissionHash, address(this), value);
        _transfer(permission.token, permission.account, value);
    }

    /// @notice Cancel payment by revoking permission and refunding all escrowed funds.
    ///
    /// @dev Reverts if not called by operator or merchant.
    ///
    /// @param permission Spend Permission for this payment.
    function void(SpendPermissionManager.SpendPermission calldata permission) external onlyOperator(permission) {
        // check sender is operator or merchant
        (address operator, address merchant,,) = decodeExtraData(permission.extraData);
        if (msg.sender != operator && msg.sender != merchant) {
            revert InvalidRefundSender(msg.sender, operator, merchant);
        }

        // revoke permission
        PERMISSION_MANAGER.revokeAsSpender(permission);

        bytes32 permissionHash = PERMISSION_MANAGER.getHash(permission);
        uint256 escrowedValue = _escrowed[permissionHash];
        if (escrowedValue == 0) return;

        delete _escrowed[permissionHash];
        emit PaymentRefunded(permissionHash, address(this), value);
        _transfer(permission.token, permission.account, escrowedValue);
    }

    /// @notice Decode `SpendPermission.extraData` into a recipient and operator address.
    function decodeExtraData(bytes calldata extraData)
        public
        pure
        returns (address operator, address merchant, uint16 feeBps, address feeRecipient)
    {
        return abi.decode(extraData, (address, address, uint16, address));
    }

    /// @notice Authorize payment by moving funds from buyer into escrow.
    function _authorize(SpendPermissionManager.SpendPermission calldata permission, uint160 value) internal {
        // check valid fee config
        (,, uint16 feeBps, address feeRecipient) = decodeExtraData(permission.extraData);
        if (feeBps > 10_000) revert FeeBpsOverflow(feeBps);
        if (feeRecipient == address(0) && feeBps != 0) revert ZeroFeeRecipient();

        // pull funds into this contract
        PERMISSION_MANAGER.spend(permission, value);

        // increase escrow accounting storage
        bytes32 permissionHash = PERMISSION_MANAGER.getHash(permission);
        _escrowed[permissionHash] += value;
        emit PaymentAuthorized(permissionHash, value);
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
