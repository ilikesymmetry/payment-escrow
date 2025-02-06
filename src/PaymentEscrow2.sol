// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";
import {IPermit2} from "permit2/interfaces/IPermit2.sol";

/// @notice Route and escrow payments using Spend Permissions (https://github.com/coinbase/spend-permissions).
/**
 * permit2 lacks:
 * - signatures are single-use so no incremental auth or subscriptions
 * - allowance storage overrides each other per-spender
 * - allowance storage doesn't support witness
 * - allowance storage doesn't parallelize nonces
 * - allowance permits don't enforce caller so signatures can be reordered and frontrun
 */
contract PaymentEscrow {
    IPermit2 public immutable PERMIT2;

    bytes32 EXTRA_DATA_TYPEHASH =
        keccak256("ExtraData(address operator,address merchant,uint16 feeBps,address feeRecipient)");

    string constant EXTRA_DATA_TYPESTRING =
        "ExtraData extraData)ExtraData(address operator,address merchant,uint16 feeBps,address feeRecipient)TokenPermissions(address token,uint256 amount)";

    struct ExtraData {
        address operator;
        address merchant;
        uint16 feeBps;
        address feeRecipient;
    }

    /// @notice Amount of tokens escrowed for a specific Spend Permission.
    ///
    /// @dev Used to limit amount that can be captured or refunded from escrow.
    mapping(bytes32 paymentId => uint256 value) internal _escrowed;

    /// @notice Amount of tokens captured for a specific Spend Permission.
    ///
    /// @dev Used to limit amount that can be refunded post-capture.
    mapping(bytes32 paymentId => uint256 value) internal _captured;

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

    receive() external payable {}

    /// @notice Validates buyer signature and transfers funds from buyer to escrow.
    ///
    /// @dev Reverts if not called by operator.
    ///
    /// @param value Amount of tokens to transfer.
    /// @param signature Signature from buyer or empty bytes.
    function authorize(
        address account,
        PermitTransferFrom memory permit,
        ExtraData extraData,
        uint160 value,
        bytes calldata signature
    ) external nonZeroValue(value) {
        // check valid fee config
        if (extraData.feeBps > 10_000) revert FeeBpsOverflow(extraData.feeBps);
        if (extraData.feeRecipient == address(0) && extraData.feeBps != 0) revert ZeroFeeRecipient();

        // pull funds into this contract
        PERMIT2.permitWitnessTransferFrom(
            permit,
            SignatureTransferDetails({to: address(this), requestedAmount: value}),
            account,
            getWitness(extraData),
            EXTRA_DATA_TYPESTRING,
            signature
        );

        bytes32 paymentId =
            keccak256(abi.encode(block.chainid, account, permit.nonce, permit.permitted.token, extraData));

        // increase escrow accounting storage
        _escrowed[paymentId] += value;
        emit PaymentAuthorized(paymentId, value);
    }

    /// @notice Transfer previously-escrowed funds to merchant.
    ///
    /// @dev Reverts if not called by operator.
    /// @dev Partial capture with custom value parameter and calling multiple times.
    ///
    /// @param value Amount of tokens to transfer.
    function capture(address account, uint256 nonce, address token, ExtraData calldata extraData, uint160 value)
        external
        nonZeroValue(value)
    {
        if (msg.sender != extraData.operator) revert InvalidSender(msg.sender, extraData.operator);

        bytes32 paymentId = keccak256(abi.encode(block.chainid, account, nonce, token, extraData));

        // check sufficient escrow to capture
        uint256 escrowedValue = _escrowed[paymentId];
        if (escrowedValue < value) revert InsufficientEscrow(paymentId, escrowedValue, value);

        // update state
        _escrowed[paymentId] -= value;
        _captured[paymentId] += value;
        emit PaymentCaptured(paymentId, value);

        // calculate fees and remaining payment value
        uint256 feeAmount = uint256(value) * extraData.feeBps / 10_000;
        value -= uint160(feeAmount);

        // transfer fee
        if (feeAmount > 0) _transfer(token, extraData.feeRecipient, feeAmount);

        // transfer payment
        if (value > 0) _transfer(token, extraData.merchant, value);
    }

    /// @notice Return previously-captured tokens to buyer.
    ///
    /// @dev Reverts if not called by operator or merchant.
    ///
    /// @param value Amount of tokens to transfer.
    function refund(address account, uint256 nonce, address token, ExtraData calldata extraData, uint160 value)
        external
        payable
        nonZeroValue(value)
    {
        // check sender is operator or merchant
        if (msg.sender != extraData.operator && msg.sender != extraData.merchant) {
            revert InvalidRefundSender(msg.sender, extraData.operator, extraData.merchant);
        }

        // limit refund value to previously captured
        bytes32 paymentId = keccak256(abi.encode(block.chainid, account, nonce, token, extraData));
        uint256 captured = _captured[paymentId];
        if (captured < value) revert RefundExceedsCapture(value, captured);

        _captured[paymentId] = captured - value;
        emit PaymentRefunded(paymentId, msg.sender, value);

        // return tokens to buyer
        if (token == NATIVE_TOKEN) {
            if (value != msg.value) revert NativeTokenValueMismatch(msg.value, value);
            SafeTransferLib.safeTransferETH(account, value);
        } else {
            SafeTransferLib.safeTransferFrom(token, msg.sender, account, value);
        }
    }

    /// @notice Return previously-escrowed funds to buyer.
    ///
    /// @dev Reverts if not called by operator or merchant.
    ///
    /// @param permission Spend Permission for this payment.
    /// @param value Amount of tokens to transfer.
    function refundFromEscrow(
        address account,
        uint256 nonce,
        address token,
        ExtraData calldata extraData,
        uint160 value
    ) external nonZeroValue(value) {
        // check sender is operator or merchant
        if (msg.sender != extraData.operator && msg.sender != extraData.merchant) {
            revert InvalidRefundSender(msg.sender, extraData.operator, extraData.merchant);
        }

        bytes32 paymentId = keccak256(abi.encode(block.chainid, account, nonce, token, extraData));
        uint256 escrowedValue = _escrowed[paymentId];
        if (escrowedValue < value) revert InsufficientEscrow(paymentId, escrowedValue, value);

        _escrowed[paymentId] -= value;
        emit PaymentRefunded(paymentId, address(this), value);
        _transfer(token, account, value);
    }

    /// @notice Cancel payment by revoking permission and refunding all escrowed funds.
    ///
    /// @dev Reverts if not called by operator or merchant.
    function void(address account, uint256 nonce, address token, ExtraData calldata extraData)
        external
        onlyOperator(permission)
    {
        // check sender is operator or merchant
        if (msg.sender != extraData.operator && msg.sender != extraData.merchant) {
            revert InvalidRefundSender(msg.sender, extraData.operator, extraData.merchant);
        }

        // Permit2 does not allow spenders to revoke, must be baked into this contract

        bytes32 paymentId = keccak256(abi.encode(block.chainid, account, nonce, token, extraData));
        uint256 escrowedValue = _escrowed[paymentId];
        if (escrowedValue == 0) return;

        delete _escrowed[paymentId];
        emit PaymentRefunded(paymentId, address(this), escrowedValue);
        _transfer(token, account, escrowedValue);
    }

    /// @notice Hash extraData
    function getWitness(ExtraData memory extraData) public pure returns (bytes32 witness) {
        return keccak256(abi.encode(EXTRA_DATA_TYPEHASH, extraData));
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
