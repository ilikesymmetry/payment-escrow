// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";
import {PublicERC6492Validator} from "spend-permissions/PublicERC6492Validator.sol";

import {IERC3009} from "./IERC3009.sol";

/// @notice Route and escrow payments using ERC-3009 authorizations.
/// @dev This contract handles payment flows where a buyer authorizes a future payment,
///      which can then be captured in parts or refunded by an operator.
contract PaymentEscrow {
    /// @notice ERC-3009 authorization with additional payment routing data
    /// @param token The ERC-3009 token contract address
    /// @param from The buyer's address authorizing the payment
    /// @param value The amount of tokens that will be transferred from the buyer to the escrow
    /// @param validAfter Timestamp when the authorization becomes valid
    /// @param validBefore Timestamp when the authorization expires
    /// @param captureDeadline Timestamp when the buyer can withdraw authorization from escrow
    /// @param operator Address authorized to capture and void payments
    /// @param captureAddress Address that receives the captured payment (minus fees)
    /// @param feeBps Fee percentage in basis points (1/100th of a percent)
    /// @param feeRecipient Address that receives the fee portion of payments
    /// @param salt A source of entropy to ensure unique hashes across different payment details
    struct Authorization {
        address token;
        address buyer;
        uint256 value;
        uint256 validAfter;
        uint256 validBefore;
        uint48 captureDeadline;
        address operator;
        address captureAddress;
        uint16 feeBps;
        address feeRecipient;
        uint256 salt;
    }

    /// @notice Whether a payment authorization has been permanently voided
    /// @dev Once voided, an authorization can never be used again
    struct AuthorizationState {
        bool isVoided;
        uint48 captureDeadline;
        uint200 balance;
    }

    /// @notice ERC-6492 magic value
    bytes32 public constant ERC6492_MAGIC_VALUE = 0x6492649264926492649264926492649264926492649264926492649264926492;

    /// @notice Validator contract for processing ERC-6492 signatures
    PublicERC6492Validator public immutable erc6492Validator;

    /// @notice Amount of tokens escrowed for a specific 3009 authorization.
    /// @dev Used to limit amount that can be captured or refunded from escrow.
    mapping(bytes32 paymentDetailsHash => AuthorizationState state) internal _authorizations;

    /// @notice Amount of tokens captured for a specific 3009 authorization.
    /// @dev Used to limit amount that can be refunded post-capture.
    mapping(bytes32 paymentDetailsHash => uint256 value) internal _captured;

    /// @notice Emitted when a payment is charged and immediately captured
    event PaymentCharged(bytes32 indexed paymentDetailsHash, uint256 value);

    /// @notice Emitted when authorized (escrowed) value is increased
    event PaymentAuthorized(bytes32 indexed paymentDetailsHash, uint256 value);

    /// @notice Emitted when a payment authorization is voided, returning any escrowed funds to the buyer
    event PaymentVoided(bytes32 indexed paymentDetailsHash);

    /// @notice Emitted when payment is captured from escrow
    event PaymentCaptured(bytes32 indexed paymentDetailsHash, uint256 value);

    /// @notice Emitted when captured payment is refunded
    event PaymentRefunded(bytes32 indexed paymentDetailsHash, address indexed refunder, uint256 value);

    error InsufficientAuthorization(bytes32 paymentDetailsHash, uint256 authorizedValue, uint256 requestedValue);
    error ValueLimitExceeded(uint256 value);
    error PermissionApprovalFailed();
    error InvalidSender(address sender);
    error BeforeCaptureDeadline(uint48 timestamp, uint48 deadline);
    error AfterCaptureDeadline(uint48 timestamp, uint48 deadline);
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
        if (msg.sender != auth.operator) revert InvalidSender(msg.sender);
        _;
    }

    /// @notice Ensures value is not zero
    modifier validValue(uint256 value) {
        if (value == 0) revert ZeroValue();
        if (value > type(uint200).max) revert ValueLimitExceeded(value);
        _;
    }

    receive() external payable {}

    /// @notice Transfers funds from buyer to captureAddress in one step
    /// @dev If value is less than the authorized value, difference is returned to buyer
    /// @param value Amount to charge and capture
    /// @param paymentDetails Encoded Authorization struct
    /// @param signature Signature of the buyer authorizing the payment
    function charge(uint256 value, bytes calldata paymentDetails, bytes calldata signature)
        external
        onlyOperator(paymentDetails)
        validValue(value)
    {
        Authorization memory auth = abi.decode(paymentDetails, (Authorization));
        bytes32 paymentDetailsHash = keccak256(abi.encode(auth));

        _pullFunds(auth, value, paymentDetailsHash, signature);

        AuthorizationState memory authState = _authorizations[paymentDetailsHash];
        // check capture deadline
        if (block.timestamp > auth.captureDeadline) {
            revert AfterCaptureDeadline(uint48(block.timestamp), authState.captureDeadline);
        }

        // Update captured amount for refund tracking
        _captured[paymentDetailsHash] = value;
        emit PaymentCharged(paymentDetailsHash, value);

        // Handle fees only for the actual charged amount
        _distributeTokens(auth.token, auth.captureAddress, auth.feeRecipient, auth.feeBps, value);
    }

    /// @notice Validates buyer signature and transfers funds from buyer to escrow
    /// @param value Amount to authorize
    /// @param paymentDetails Encoded Authorization struct
    /// @param signature Signature of the buyer authorizing the payment
    function authorize(uint256 value, bytes calldata paymentDetails, bytes calldata signature)
        external
        onlyOperator(paymentDetails)
        validValue(value)
    {
        Authorization memory auth = abi.decode(paymentDetails, (Authorization));
        bytes32 paymentDetailsHash = keccak256(abi.encode(auth));

        _pullFunds(auth, value, paymentDetailsHash, signature);

        // Update authorized amount to only what we're keeping
        _authorizations[paymentDetailsHash] =
            AuthorizationState({isVoided: false, captureDeadline: auth.captureDeadline, balance: uint200(value)});
        emit PaymentAuthorized(paymentDetailsHash, value);
    }

    /// @notice Permanently voids a payment authorization
    /// @dev Returns any escrowed funds to buyer
    /// @param paymentDetails Encoded Authorization struct
    function void(bytes calldata paymentDetails) external {
        Authorization memory auth = abi.decode(paymentDetails, (Authorization));
        bytes32 paymentDetailsHash = keccak256(abi.encode(auth));

        if (msg.sender == auth.buyer) {
            if (block.timestamp < auth.captureDeadline) {
                revert BeforeCaptureDeadline(uint48(block.timestamp), auth.captureDeadline);
            }
        } else if (msg.sender != auth.operator && msg.sender != auth.captureAddress) {
            revert InvalidSender(msg.sender);
        }

        // early return if previously voided
        AuthorizationState memory authState = _authorizations[paymentDetailsHash];
        if (authState.isVoided) return;

        // Mark the authorization as void
        _authorizations[paymentDetailsHash].isVoided = true;
        emit PaymentVoided(paymentDetailsHash);

        // early return if no existing authorization escrowed
        uint256 authorizedValue = authState.balance;
        if (authorizedValue == 0) return;

        // Return any escrowed funds
        _authorizations[paymentDetailsHash].balance = 0;
        SafeTransferLib.safeTransfer(auth.token, auth.buyer, authorizedValue);
    }

    /// @notice Transfer previously-escrowed funds to captureAddress
    /// @dev Can be called multiple times up to cumulative authorized amount
    /// @param value Amount to capture
    /// @param paymentDetails Encoded Authorization struct
    function capture(uint256 value, bytes calldata paymentDetails)
        external
        onlyOperator(paymentDetails)
        validValue(value)
    {
        Authorization memory auth = abi.decode(paymentDetails, (Authorization));
        bytes32 paymentDetailsHash = keccak256(abi.encode(auth));

        // check capture deadline
        AuthorizationState memory authState = _authorizations[paymentDetailsHash];
        if (block.timestamp > authState.captureDeadline) {
            revert AfterCaptureDeadline(uint48(block.timestamp), authState.captureDeadline);
        }

        // check sufficient escrow to capture
        uint256 authorizedValue = authState.balance;
        if (authorizedValue < value) revert InsufficientAuthorization(paymentDetailsHash, authorizedValue, value);

        // update state
        authState.balance -= uint200(value);
        _authorizations[paymentDetailsHash] = authState;
        _captured[paymentDetailsHash] += value;
        emit PaymentCaptured(paymentDetailsHash, value);

        // handle fees only for the actual charged amount
        _distributeTokens(auth.token, auth.captureAddress, auth.feeRecipient, auth.feeBps, value);
    }

    /// @notice Return previously-captured tokens to buyer
    /// @dev Can be called by operator or captureAddress
    /// @param value Amount to refund
    /// @param paymentDetails Encoded Authorization struct
    function refund(uint256 value, bytes calldata paymentDetails) external validValue(value) {
        Authorization memory auth = abi.decode(paymentDetails, (Authorization));
        bytes32 paymentDetailsHash = keccak256(abi.encode(auth));

        // Check sender is operator or captureAddress
        if (msg.sender != auth.operator && msg.sender != auth.captureAddress) {
            revert InvalidSender(msg.sender);
        }

        // Limit refund value to previously captured
        uint256 captured = _captured[paymentDetailsHash];
        if (captured < value) revert RefundExceedsCapture(value, captured);

        _captured[paymentDetailsHash] = captured - value;
        emit PaymentRefunded(paymentDetailsHash, msg.sender, value);

        // Return tokens to buyer
        SafeTransferLib.safeTransferFrom(auth.token, msg.sender, auth.buyer, value);
    }

    function _pullFunds(Authorization memory auth, uint256 value, bytes32 paymentDetailsHash, bytes calldata signature)
        internal
    {
        // validate value
        if (value > auth.value) revert ValueLimitExceeded(value);

        // validate fees
        if (auth.feeBps > 10_000) revert FeeBpsOverflow(auth.feeBps);
        if (auth.feeRecipient == address(0) && auth.feeBps != 0) revert ZeroFeeRecipient();

        // check if authorization has been voided
        if (_authorizations[paymentDetailsHash].isVoided) revert VoidAuthorization(paymentDetailsHash);

        // parse signature to use for 3009 receiveWithAuthorization
        bytes memory innerSignature = signature;
        if (signature.length >= 32 && bytes32(signature[signature.length - 32:]) == ERC6492_MAGIC_VALUE) {
            // apply 6492 signature prepareData
            erc6492Validator.isValidSignatureNowAllowSideEffects(auth.buyer, paymentDetailsHash, signature);
            // parse inner signature from 6492 format
            (,, innerSignature) = abi.decode(signature[0:signature.length - 32], (address, bytes, bytes));
        }

        // pull the full authorized amount from the buyer
        IERC3009(auth.token).receiveWithAuthorization(
            auth.buyer, address(this), auth.value, auth.validAfter, auth.validBefore, paymentDetailsHash, innerSignature
        );

        // send excess funds back to buyer
        uint256 excessFunds = auth.value - value;
        if (excessFunds > 0) SafeTransferLib.safeTransfer(auth.token, auth.buyer, excessFunds);
    }

    /// @notice Sends tokens to captureAddress and/or feeRecipient
    /// @param token Token to transfer
    /// @param captureAddress Address to receive payment
    /// @param feeRecipient Address to receive fees
    /// @param feeBps Fee percentage in basis points
    /// @param value Total amount to split between payment and fees
    /// @return remainingValue Amount after fees deducted
    function _distributeTokens(
        address token,
        address captureAddress,
        address feeRecipient,
        uint16 feeBps,
        uint256 value
    ) internal returns (uint256 remainingValue) {
        uint256 feeAmount = uint256(value) * feeBps / 10_000;
        remainingValue = value - feeAmount;

        if (feeAmount > 0) SafeTransferLib.safeTransfer(token, feeRecipient, feeAmount);
        if (remainingValue > 0) SafeTransferLib.safeTransfer(token, captureAddress, remainingValue);
    }
}
