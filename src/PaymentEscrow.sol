// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";
import {IERC3009} from "./IERC3009.sol";
import {PublicERC6492Validator} from "spend-permissions/PublicERC6492Validator.sol";

/// @notice Route and escrow payments using ERC-3009 authorizations.
/// @dev This contract handles payment flows where a buyer authorizes a future payment,
///      which can then be captured in parts or refunded by an operator.
contract PaymentEscrow {
    /// @notice ERC-3009 authorization with additional payment routing data
    /// @param token The ERC-3009 token contract address
    /// @param from The buyer's address authorizing the payment
    /// @param to The payment escrow contract address
    /// @param validAfter Timestamp when the authorization becomes valid
    /// @param validBefore Timestamp when the authorization expires
    /// @param value The amount of tokens that will be transferred from the buyer to the escrow
    /// @param extraData Additional payment routing and fee data
    struct Authorization {
        address token;
        address from;
        address to;
        uint256 validAfter;
        uint256 validBefore;
        uint256 value;
        ExtraData extraData;
    }

    /// @notice Additional data to complement ERC-3009 base fields
    /// @param salt A source of entropy to ensure unique hashes across different payment details
    /// @param operator Address authorized to capture and void payments
    /// @param captureAddress Address that receives the captured payment (minus fees)
    /// @param feeBps Fee percentage in basis points (1/100th of a percent)
    /// @param feeRecipient Address that receives the fee portion of payments
    struct ExtraData {
        uint256 salt;
        address operator;
        address captureAddress;
        uint16 feeBps;
        address feeRecipient;
    }

    /// @notice ERC-6492 magic value
    bytes32 public constant ERC6492_MAGIC_VALUE = 0x6492649264926492649264926492649264926492649264926492649264926492;

    /// @notice Validator contract for processing ERC-6492 signatures
    PublicERC6492Validator public immutable erc6492Validator;

    /// @notice Amount of tokens escrowed for a specific 3009 authorization.
    /// @dev Used to limit amount that can be captured or refunded from escrow.
    mapping(bytes32 paymentDetailsHash => uint256 value) internal _authorized;

    /// @notice Amount of tokens captured for a specific 3009 authorization.
    /// @dev Used to limit amount that can be refunded post-capture.
    mapping(bytes32 paymentDetailsHash => uint256 value) internal _captured;

    /// @notice Whether a payment authorization has been permanently voided
    /// @dev Once voided, an authorization can never be used again
    mapping(bytes32 paymentDetailsHash => bool isVoid) internal _voided;

    /// @notice Emitted when a payment is charged and immediately captured
    event PaymentCharged(bytes32 indexed paymentDetailsHash, uint256 value);

    /// @notice Emitted when authorized (escrowed) value is increased
    event AuthorizationIncreased(bytes32 indexed paymentDetailsHash, uint256 value);

    /// @notice Emitted when authorized (escrowed) value is decreased
    event AuthorizationDecreased(bytes32 indexed paymentDetailsHash, uint256 value);

    /// @notice Emitted when a payment authorization is voided, returning any escrowed funds to the buyer
    event PaymentVoided(bytes32 indexed paymentDetailsHash);

    /// @notice Emitted when payment is captured from escrow
    event PaymentCaptured(bytes32 indexed paymentDetailsHash, uint256 value);

    /// @notice Emitted when captured payment is refunded
    event PaymentRefunded(bytes32 indexed paymentDetailsHash, address indexed refunder, uint256 value);

    error InsufficientAuthorization(bytes32 paymentDetailsHash, uint256 authorizedValue, uint256 requestedValue);
    error ValueLimitExceeded(uint256 value);
    error PermissionApprovalFailed();
    error InvalidSender(address sender, address expected);
    error InvalidRefundSender(address sender, address operator, address captureAddress);
    error RefundExceedsCapture(uint256 refund, uint256 captured);
    error FeeBpsOverflow(uint16 feeBps);
    error ZeroFeeRecipient();
    error ZeroValue();
    error VoidAuthorization(bytes32 paymentDetailsHash);

    /// @notice Initialize contract with ERC6492 validator
    /// @param _erc6492Validator Address of the validator contract
    constructor(address _erc6492Validator) {
        erc6492Validator = PublicERC6492Validator(_erc6492Validator);
    }

    /// @notice Ensures caller is the operator specified in payment details
    modifier onlyOperator(bytes calldata paymentDetails) {
        Authorization memory auth = abi.decode(paymentDetails, (Authorization));
        ExtraData memory data = auth.extraData;
        if (msg.sender != data.operator) revert InvalidSender(msg.sender, data.operator);
        _;
    }

    /// @notice Ensures value is not zero
    modifier nonZeroValue(uint256 value) {
        if (value == 0) revert ZeroValue();
        _;
    }

    receive() external payable {}

    /// @notice Transfers funds from buyer to captureAddress in one step
    /// @dev If valueToCharge is less than the authorized value, difference is returned to buyer
    /// @param valueToCharge Amount to charge and capture
    /// @param paymentDetails Encoded Authorization struct
    /// @param signature Signature of the buyer authorizing the payment
    function charge(uint256 valueToCharge, bytes calldata paymentDetails, bytes calldata signature)
        external
        onlyOperator(paymentDetails)
        nonZeroValue(valueToCharge)
    {
        Authorization memory auth = abi.decode(paymentDetails, (Authorization));
        bytes32 paymentDetailsHash = keccak256(abi.encode(auth));

        // Cache token to reduce struct access
        address token = auth.token;

        // Validate and execute transfer
        _validateChargeInputs(valueToCharge, auth);
        _executeReceiveWithAuth(auth, auth.value, paymentDetailsHash, signature);

        // Update state and emit event
        _captured[paymentDetailsHash] = valueToCharge;
        emit PaymentCharged(paymentDetailsHash, valueToCharge);

        // Handle refund if needed
        uint256 refundAmount = auth.value - valueToCharge;
        if (refundAmount > 0) {
            _transfer(token, auth.from, refundAmount);
        }

        // Handle fees separately to reduce stack
        _handleChargeFeesAndTransfer(token, valueToCharge, auth.extraData);
    }

    function _validateChargeInputs(uint256 valueToCharge, Authorization memory auth) internal pure {
        if (valueToCharge > auth.value) {
            revert ValueLimitExceeded(valueToCharge);
        }
        _validateFees(auth.extraData.feeBps, auth.extraData.feeRecipient);
    }

    function _handleChargeFeesAndTransfer(address token, uint256 value, ExtraData memory data) internal {
        uint256 feeAmount = value * data.feeBps / 10_000;
        uint256 remainingValue = value - feeAmount;

        if (feeAmount > 0) _transfer(token, data.feeRecipient, feeAmount);
        if (remainingValue > 0) _transfer(token, data.captureAddress, remainingValue);
    }

    /// @notice Validates buyer signature and transfers funds from buyer to escrow
    /// @param valueToConfirm Amount to authorize
    /// @param paymentDetails Encoded Authorization struct
    /// @param signature Signature of the buyer authorizing the payment
    function confirmAuthorization(uint256 valueToConfirm, bytes calldata paymentDetails, bytes calldata signature)
        external
        onlyOperator(paymentDetails)
        nonZeroValue(valueToConfirm)
    {
        Authorization memory auth = abi.decode(paymentDetails, (Authorization));
        ExtraData memory data = auth.extraData;

        if (valueToConfirm > auth.value) {
            revert ValueLimitExceeded(valueToConfirm);
        }

        _validateFees(data.feeBps, data.feeRecipient);

        bytes32 paymentDetailsHash = keccak256(abi.encode(auth));

        // Pull the full authorized amount from the buyer
        _executeReceiveWithAuth(auth, auth.value, paymentDetailsHash, signature);

        // Update authorized amount to only what we're keeping
        _authorized[paymentDetailsHash] += valueToConfirm;
        emit AuthorizationIncreased(paymentDetailsHash, valueToConfirm);

        // Refund any excess amount
        _refundExtraAuthorizedAmount(auth, auth.value, valueToConfirm);
    }

    /// @notice Permanently voids a payment authorization
    /// @dev Returns any escrowed funds to buyer
    /// @param paymentDetails Encoded Authorization struct
    function voidAuthorization(bytes calldata paymentDetails) external {
        Authorization memory auth = abi.decode(paymentDetails, (Authorization));
        ExtraData memory data = auth.extraData;

        // Check sender is operator or captureAddress
        if (msg.sender != data.operator && msg.sender != data.captureAddress) {
            revert InvalidRefundSender(msg.sender, data.operator, data.captureAddress);
        }

        bytes32 paymentDetailsHash = keccak256(abi.encode(auth));

        // Mark the authorization as void
        _voided[paymentDetailsHash] = true;
        emit PaymentVoided(paymentDetailsHash);

        // Return any escrowed funds
        uint256 authorizedValue = _authorized[paymentDetailsHash];
        if (authorizedValue == 0) return;

        delete _authorized[paymentDetailsHash];
        emit AuthorizationDecreased(paymentDetailsHash, authorizedValue);
        emit PaymentVoided(paymentDetailsHash);
        _transfer(auth.token, auth.from, authorizedValue);
    }

    /// @notice Transfer previously-escrowed funds to captureAddress
    /// @dev Can be called multiple times up to cumulative authorized amount
    /// @param value Amount to capture
    /// @param paymentDetails Encoded Authorization struct
    function captureAuthorization(uint256 value, bytes calldata paymentDetails)
        external
        onlyOperator(paymentDetails)
        nonZeroValue(value)
    {
        Authorization memory auth = abi.decode(paymentDetails, (Authorization));
        ExtraData memory data = auth.extraData;
        bytes32 paymentDetailsHash = keccak256(abi.encode(auth));

        // Check sufficient escrow to capture
        uint256 authorizedValue = _authorized[paymentDetailsHash];
        if (authorizedValue < value) revert InsufficientAuthorization(paymentDetailsHash, authorizedValue, value);

        // Update state
        _authorized[paymentDetailsHash] = authorizedValue - value;
        _captured[paymentDetailsHash] += value;
        emit PaymentCaptured(paymentDetailsHash, value);

        // Calculate fees and remaining payment value
        uint256 feeAmount = uint256(value) * data.feeBps / 10_000;
        value -= uint256(feeAmount);

        // Transfer fee
        if (feeAmount > 0) _transfer(auth.token, data.feeRecipient, feeAmount);

        // Transfer payment
        if (value > 0) _transfer(auth.token, data.captureAddress, value);
    }

    /// @notice Return previously-captured tokens to buyer
    /// @dev Can be called by operator or captureAddress
    /// @param value Amount to refund
    /// @param paymentDetails Encoded Authorization struct
    function refund(uint256 value, bytes calldata paymentDetails) external nonZeroValue(value) {
        Authorization memory auth = abi.decode(paymentDetails, (Authorization));
        ExtraData memory data = auth.extraData;

        // Check sender is operator or captureAddress
        if (msg.sender != data.operator && msg.sender != data.captureAddress) {
            revert InvalidRefundSender(msg.sender, data.operator, data.captureAddress);
        }

        // Limit refund value to previously captured
        bytes32 paymentDetailsHash = keccak256(abi.encode(auth));
        uint256 captured = _captured[paymentDetailsHash];
        if (captured < value) revert RefundExceedsCapture(value, captured);

        _captured[paymentDetailsHash] = captured - value;
        emit PaymentRefunded(paymentDetailsHash, msg.sender, value);

        // Return tokens to buyer
        SafeTransferLib.safeTransferFrom(auth.token, msg.sender, auth.from, value);
    }

    /// @notice Execute ERC3009 receiveWithAuthorization with signature validation
    /// @param auth Authorization struct containing transfer details
    /// @param value Amount to transfer
    /// @param paymentDetailsHash Hash of encoded Authorization struct
    /// @param signature ERC-3009 or ERC-6492 signature
    function _executeReceiveWithAuth(
        Authorization memory auth,
        uint256 value,
        bytes32 paymentDetailsHash,
        bytes calldata signature
    ) internal {
        // Check if authorization has been voided
        if (_voided[paymentDetailsHash]) {
            revert VoidAuthorization(paymentDetailsHash);
        }

        bytes memory innerSignature = signature;
        if (signature.length >= 32 && bytes32(signature[signature.length - 32:]) == ERC6492_MAGIC_VALUE) {
            // Deploy smart wallet if needed
            erc6492Validator.isValidSignatureNowAllowSideEffects(auth.from, paymentDetailsHash, signature);
            // If it's an ERC6492 signature, unwrap it to get the inner signature
            (,, innerSignature) = abi.decode(signature[0:signature.length - 32], (address, bytes, bytes));
        }

        IERC3009(auth.token).receiveWithAuthorization(
            auth.from, address(this), value, auth.validAfter, auth.validBefore, paymentDetailsHash, innerSignature
        );
    }

    /// @notice Validate fee configuration
    /// @param feeBps Fee percentage in basis points
    /// @param feeRecipient Address to receive fees
    function _validateFees(uint16 feeBps, address feeRecipient) internal pure {
        if (feeBps > 10_000) revert FeeBpsOverflow(feeBps);
        if (feeRecipient == address(0) && feeBps != 0) revert ZeroFeeRecipient();
    }

    /// @dev Helper to refund any excess authorized amount back to the buyer
    function _refundExtraAuthorizedAmount(Authorization memory auth, uint256 authorizedAmount, uint256 keepAmount)
        internal
    {
        // Calculate difference to refund
        uint256 refundAmount = authorizedAmount - keepAmount;

        // Return excess funds to buyer if any
        if (refundAmount > 0) {
            _transfer(auth.token, auth.from, refundAmount);
        }
    }

    /// @notice Transfer tokens from the escrow to a recipient
    /// @param token Token to transfer
    /// @param recipient Address to receive tokens
    /// @param value Amount to transfer
    function _transfer(address token, address recipient, uint256 value) internal {
        SafeTransferLib.safeTransfer(token, recipient, value);
    }
}
