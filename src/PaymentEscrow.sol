// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";
import {ISignatureTransfer} from "permit2/interfaces/ISignatureTransfer.sol";

/// @notice Route and escrow payments using Spend Permissions (https://github.com/coinbase/spend-permissions).
contract PaymentEscrow {
    /// @notice ABI-encoded data packed into `SpendPermission.extraData` field.
    struct ExtraData {
        address operator;
        address merchant;
        uint16 feeBps;
        address feeRecipient;
    }

    bytes32 public constant EXTRA_DATA_TYPEHASH =
        keccak256("ExtraData(address operator,address merchant,uint16 feeBps,address feeRecipient)");

    string public constant EXTRA_DATA_TYPESTRING =
        "ExtraData extraData)ExtraData(address operator,address merchant,uint16 feeBps,address feeRecipient)TokenPermissions(address token,uint256 amount)";

    ISignatureTransfer public immutable PERMIT2;

    /// @notice Amount of tokens escrowed for a specific Spend Permission.
    /// @dev Used to limit amount that can be captured or refunded from escrow.
    mapping(bytes32 paymentDetailsHash => uint256 value) internal _authorized;

    /// @notice Amount of tokens captured for a specific Spend Permission.
    /// @dev Used to limit amount that can be refunded post-capture.
    mapping(bytes32 permissionhash => uint256 value) internal _captured;

    /// @notice Payment charged to buyer and immediately captured.
    event Charged(bytes32 indexed paymentDetailsHash, uint256 value);

    /// @notice Payment authorized, increasing value escrowed.
    event AuthorizationIncreased(bytes32 indexed paymentDetailsHash, uint256 value);

    /// @notice Payment authorization reduced, decreasing value escrowed.
    event AuthorizationDecreased(bytes32 indexed paymentDetailsHash, uint256 value);

    /// @notice Payment refunded to buyer, descreasing value escrowed.
    event Voided(bytes32 indexed paymentDetailsHash);

    /// @notice Payment captured, descreasing value escrowed.
    event Captured(bytes32 indexed paymentDetailsHash, uint256 value);

    /// @notice Payment refunded to buyer.
    event Refunded(bytes32 indexed paymentDetailsHash, address indexed refunder, uint256 value);

    error InsufficientAuthorization(bytes32 paymentDetailsHash, uint256 authorizedValue, uint256 requestedValue);
    error ValueLimitExceeded(uint256 value);
    error PermissionApprovalFailed();
    error InvalidSender(address sender, address expected);
    error InvalidRefundSender(address sender, address operator, address merchant);
    error RefundExceedsCapture(uint256 refund, uint256 captured);
    error NativeTokenValueMismatch(uint256 msgValue, uint256 argValue);
    error FeeBpsOverflow(uint16 feeBps);
    error ZeroFeeRecipient();
    error ZeroValue();

    modifier onlyOperator(bytes calldata paymentDetails) {
        (address account, ISignatureTransfer.PermitTransferFrom memory permit, ExtraData memory data) =
            abi.decode(paymentDetails, (address, ISignatureTransfer.PermitTransferFrom, ExtraData));
        if (msg.sender != data.operator) revert InvalidSender(msg.sender, data.operator);
        _;
    }

    modifier nonZeroValue(uint256 value) {
        if (value == 0) revert ZeroValue();
        _;
    }

    constructor(address permit2) {
        PERMIT2 = ISignatureTransfer(permit2);
    }

    function charge(uint256 value, bytes calldata paymentDetails, bytes calldata signature)
        external
        onlyOperator(paymentDetails)
    {
        (address account, ISignatureTransfer.PermitTransferFrom memory permit, ExtraData memory data) =
            abi.decode(paymentDetails, (address, ISignatureTransfer.PermitTransferFrom, ExtraData));

        // check valid fee config
        if (data.feeBps > 10_000) revert FeeBpsOverflow(data.feeBps);
        if (data.feeRecipient == address(0) && data.feeBps != 0) revert ZeroFeeRecipient();

        // pull funds into this contract
        PERMIT2.permitWitnessTransferFrom(
            permit,
            ISignatureTransfer.SignatureTransferDetails({to: address(this), requestedAmount: value}),
            account,
            keccak256(abi.encode(EXTRA_DATA_TYPEHASH, data)),
            EXTRA_DATA_TYPESTRING,
            signature
        );
        bytes32 paymentDetailsHash = keccak256(abi.encode(block.chainid, account, permit.nonce, data));
        emit Charged(paymentDetailsHash, value);

        // calculate fees and remaining payment value
        uint256 feeAmount = uint256(value) * data.feeBps / 10_000;
        value -= uint256(feeAmount);

        // transfer fee
        if (feeAmount > 0) _transfer(permit.permitted.token, data.feeRecipient, feeAmount);

        // transfer payment
        if (value > 0) _transfer(permit.permitted.token, data.merchant, value);
    }

    /// @notice Validates buyer signature and transfers funds from buyer to escrow.
    /// @dev Reverts if not called by operator.
    function authorize(uint256 value, bytes calldata paymentDetails, bytes calldata signature)
        external
        onlyOperator(paymentDetails)
        nonZeroValue(value)
    {
        (address account, ISignatureTransfer.PermitTransferFrom memory permit, ExtraData memory data) =
            abi.decode(paymentDetails, (address, ISignatureTransfer.PermitTransferFrom, ExtraData));

        // check valid fee config
        if (data.feeBps > 10_000) revert FeeBpsOverflow(data.feeBps);
        if (data.feeRecipient == address(0) && data.feeBps != 0) revert ZeroFeeRecipient();

        // pull funds into this contract
        PERMIT2.permitWitnessTransferFrom(
            permit,
            ISignatureTransfer.SignatureTransferDetails({to: address(this), requestedAmount: value}),
            account,
            keccak256(abi.encode(EXTRA_DATA_TYPEHASH, data)),
            EXTRA_DATA_TYPESTRING,
            signature
        );
        bytes32 paymentDetailsHash = keccak256(abi.encode(block.chainid, account, permit.nonce, data));
        _authorized[paymentDetailsHash] += value;
        emit AuthorizationIncreased(paymentDetailsHash, value);
    }

    /// @notice Return previously-escrowed funds to buyer.
    /// @dev Reverts if not called by operator or merchant.
    function decreaseAuthorization(uint256 value, bytes calldata paymentDetails)
        external
        onlyOperator(paymentDetails)
        nonZeroValue(value)
    {
        (address account, ISignatureTransfer.PermitTransferFrom memory permit, ExtraData memory data) =
            abi.decode(paymentDetails, (address, ISignatureTransfer.PermitTransferFrom, ExtraData));
        bytes32 paymentDetailsHash = keccak256(abi.encode(block.chainid, account, permit.nonce, data));

        // check sufficient authorization
        uint256 authorizedValue = _authorized[paymentDetailsHash];
        if (authorizedValue < value) revert InsufficientAuthorization(paymentDetailsHash, authorizedValue, value);

        _authorized[paymentDetailsHash] = authorizedValue - value;
        emit AuthorizationDecreased(paymentDetailsHash, value);
        _transfer(permit.permitted.token, account, value);
    }

    /// @notice Cancel payment by revoking permission and refunding all escrowed funds.
    /// @dev Reverts if not called by operator or merchant.
    function void(bytes calldata paymentDetails) external onlyOperator(paymentDetails) {
        (address account, ISignatureTransfer.PermitTransferFrom memory permit, ExtraData memory data) =
            abi.decode(paymentDetails, (address, ISignatureTransfer.PermitTransferFrom, ExtraData));
        bytes32 paymentDetailsHash = keccak256(abi.encode(block.chainid, account, permit.nonce, data));

        // early return if no authorized value
        uint256 authorizedValue = _authorized[paymentDetailsHash];
        if (authorizedValue == 0) return;

        delete _authorized[paymentDetailsHash];
        emit AuthorizationDecreased(paymentDetailsHash, authorizedValue);
        emit Voided(paymentDetailsHash);
        _transfer(permit.permitted.token, account, authorizedValue);
    }

    /// @notice Transfer previously-escrowed funds to merchant.
    /// @dev Reverts if not called by operator.
    /// @dev Partial capture with custom value parameter and calling multiple times.
    function capture(uint256 value, bytes calldata paymentDetails)
        external
        onlyOperator(paymentDetails)
        nonZeroValue(value)
    {
        (address account, ISignatureTransfer.PermitTransferFrom memory permit, ExtraData memory data) =
            abi.decode(paymentDetails, (address, ISignatureTransfer.PermitTransferFrom, ExtraData));
        bytes32 paymentDetailsHash = keccak256(abi.encode(block.chainid, account, permit.nonce, data));

        // check sufficient escrow to capture
        uint256 authorizedValue = _authorized[paymentDetailsHash];
        if (authorizedValue < value) revert InsufficientAuthorization(paymentDetailsHash, authorizedValue, value);

        // update state
        _authorized[paymentDetailsHash] = authorizedValue - value;
        _captured[paymentDetailsHash] += value;
        emit Captured(paymentDetailsHash, value);

        // calculate fees and remaining payment value
        uint256 feeAmount = uint256(value) * data.feeBps / 10_000;
        value -= uint256(feeAmount);

        // transfer fee
        if (feeAmount > 0) _transfer(permit.permitted.token, data.feeRecipient, feeAmount);

        // transfer payment
        if (value > 0) _transfer(permit.permitted.token, data.merchant, value);
    }

    /// @notice Return previously-captured tokens to buyer.
    /// @dev Reverts if not called by operator or merchant.
    function refund(uint256 value, bytes calldata paymentDetails) external nonZeroValue(value) {
        (address account, ISignatureTransfer.PermitTransferFrom memory permit, ExtraData memory data) =
            abi.decode(paymentDetails, (address, ISignatureTransfer.PermitTransferFrom, ExtraData));
        bytes32 paymentDetailsHash = keccak256(abi.encode(block.chainid, account, permit.nonce, data));

        // check sender is operator or merchant
        if (msg.sender != data.operator && msg.sender != data.merchant) {
            revert InvalidRefundSender(msg.sender, data.operator, data.merchant);
        }

        // limit refund value to previously captured
        uint256 captured = _captured[paymentDetailsHash];
        if (captured < value) revert RefundExceedsCapture(value, captured);

        _captured[paymentDetailsHash] = captured - value;
        emit Refunded(paymentDetailsHash, msg.sender, value);

        // return tokens to buyer
        SafeTransferLib.safeTransferFrom(permit.permitted.token, msg.sender, account, value);
    }

    /// @notice Transfer tokens from the escrow to a recipient.
    function _transfer(address token, address recipient, uint256 value) internal {
        SafeTransferLib.safeTransfer(token, recipient, value);
    }
}
