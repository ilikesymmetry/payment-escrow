// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";
import {IERC3009} from "./IERC3009.sol";
import {PublicERC6492Validator} from "spend-permissions/PublicERC6492Validator.sol";

/// @notice Route and escrow payments using ERC-3009 authorizations.
contract PaymentEscrow {
    /// @notice Additional data to compliment ERC-3009 base fields
    struct ExtraData {
        uint256 salt;
        address operator;
        address captureAddress;
        uint16 feeBps;
        address feeRecipient;
    }

    /// @notice ERC-3009 authorization
    struct Authorization {
        address token;
        address from;
        address to;
        uint256 validAfter;
        uint256 validBefore;
        uint256 value; // represents the amount of tokens that will be passed to receiveWithAuthorization (signed over)
        ExtraData extraData;
    }

    /// @notice ERC-6492 magic value
    bytes32 public constant ERC6492_MAGIC_VALUE = 0x6492649264926492649264926492649264926492649264926492649264926492;

    /// @notice ERC-6492 validator
    PublicERC6492Validator public immutable erc6492Validator;

    /// @notice Amount of tokens escrowed for a specific 3009 authorization.
    /// @dev Used to limit amount that can be captured or refunded from escrow.
    mapping(bytes32 paymentDetailsHash => uint256 value) internal _authorized;

    /// @notice Amount of tokens captured for a specific 3009 authorization.
    /// @dev Used to limit amount that can be refunded post-capture.
    mapping(bytes32 paymentDetailsHash => uint256 value) internal _captured;

    /// @notice Payment charged to buyer and immediately captured.
    event Charged(bytes32 indexed paymentDetailsHash, uint256 value);

    /// @notice Payment authorized, increasing value escrowed.
    event AuthorizationIncreased(bytes32 indexed paymentDetailsHash, uint256 value);

    /// @notice Payment authorization reduced, decreasing value escrowed.
    event AuthorizationDecreased(bytes32 indexed paymentDetailsHash, uint256 value);

    /// @notice Payment refunded to buyer, descreasing value escrowed.
    event AuthorizationVoided(bytes32 indexed paymentDetailsHash);

    /// @notice Payment captured, descreasing value escrowed.
    event AuthorizationCaptured(bytes32 indexed paymentDetailsHash, uint256 value);

    /// @notice Payment refunded to buyer.
    event Refunded(bytes32 indexed paymentDetailsHash, address indexed refunder, uint256 value);

    error InsufficientAuthorization(bytes32 paymentDetailsHash, uint256 authorizedValue, uint256 requestedValue);
    error ValueLimitExceeded(uint256 value);
    error PermissionApprovalFailed();
    error InvalidSender(address sender, address expected);
    error InvalidRefundSender(address sender, address operator, address captureAddress);
    error RefundExceedsCapture(uint256 refund, uint256 captured);
    error FeeBpsOverflow(uint16 feeBps);
    error ZeroFeeRecipient();
    error ZeroValue();
    error Unsupported();
    error InvalidSignature();

    constructor(address _erc6492Validator) {
        erc6492Validator = PublicERC6492Validator(_erc6492Validator);
    }

    modifier onlyOperator(bytes calldata paymentDetails) {
        Authorization memory auth = abi.decode(paymentDetails, (Authorization));
        ExtraData memory data = auth.extraData;
        if (msg.sender != data.operator) revert InvalidSender(msg.sender, data.operator);
        _;
    }

    modifier nonZeroValue(uint256 value) {
        if (value == 0) revert ZeroValue();
        _;
    }

    receive() external payable {}

    /// @notice Transfers funds from buyer to captureAddress.
    function charge(uint256 value, bytes calldata paymentDetails, bytes calldata signature)
        external
        onlyOperator(paymentDetails)
    {
        Authorization memory auth = abi.decode(paymentDetails, (Authorization));
        ExtraData memory data = auth.extraData;

        _validateFees(data.feeBps, data.feeRecipient);

        bytes32 paymentDetailsHash = keccak256(abi.encode(auth));

        _executeReceiveWithAuth(auth, value, paymentDetailsHash, signature);
        emit Charged(paymentDetailsHash, value);

        _handleFees(auth.token, data.captureAddress, data.feeRecipient, data.feeBps, value);
    }

    /// @notice Validates buyer signature and transfers funds from buyer to escrow.
    /// @dev Reverts if not called by operator.
    function confirmAuthorization(uint256 value, bytes calldata paymentDetails, bytes calldata signature)
        external
        onlyOperator(paymentDetails)
        nonZeroValue(value)
    {
        // TODO: for this function and for `charge`
        // diff arg value v.s. auth.value
        // if diff is nonzero, return the diff amount to the buyer at end of txn
        // increment authorized storage only by what was kept
        Authorization memory auth = abi.decode(paymentDetails, (Authorization));
        ExtraData memory data = auth.extraData;

        _validateFees(data.feeBps, data.feeRecipient);

        bytes32 paymentDetailsHash = keccak256(abi.encode(auth));
        _executeReceiveWithAuth(auth, value, paymentDetailsHash, signature);

        _authorized[paymentDetailsHash] += value; // todo only kept amount
        emit AuthorizationIncreased(paymentDetailsHash, value);
    }

    /// @notice Cancel payment by revoking authorization and refunding all escrowed funds.
    /// @dev Reverts if not called by operator or captureAddress.
    function voidAuthorization(bytes calldata paymentDetails) external onlyOperator(paymentDetails) {
        Authorization memory auth = abi.decode(paymentDetails, (Authorization));
        // ExtraData memory data = auth.extraData;
        bytes32 paymentDetailsHash = keccak256(abi.encode(auth));

        // TODO: revoke authorization -- via the 3009 revoke function (can't, needs signature)
        // could add a voiding storage to this contract to revoke here

        // early return if no authorized value
        uint256 authorizedValue = _authorized[paymentDetailsHash];
        if (authorizedValue == 0) return;

        delete _authorized[paymentDetailsHash];
        emit AuthorizationDecreased(paymentDetailsHash, authorizedValue);
        emit AuthorizationVoided(paymentDetailsHash);
        _transfer(auth.token, auth.from, authorizedValue);
    }

    /// @notice Transfer previously-escrowed funds to captureAddress.
    /// @dev Reverts if not called by operator.
    /// @dev Partial capture with custom value parameter and calling multiple times.
    /// TODO: maybe just pass the hash here and anything else needed?
    function captureAuthorization(uint256 value, bytes calldata paymentDetails)
        external
        onlyOperator(paymentDetails)
        nonZeroValue(value)
    {
        Authorization memory auth = abi.decode(paymentDetails, (Authorization));
        ExtraData memory data = auth.extraData;
        bytes32 paymentDetailsHash = keccak256(abi.encode(auth));

        // check sufficient escrow to capture
        uint256 authorizedValue = _authorized[paymentDetailsHash];
        if (authorizedValue < value) revert InsufficientAuthorization(paymentDetailsHash, authorizedValue, value);

        // update state
        _authorized[paymentDetailsHash] = authorizedValue - value;
        _captured[paymentDetailsHash] += value;
        emit AuthorizationCaptured(paymentDetailsHash, value);

        // calculate fees and remaining payment value
        uint256 feeAmount = uint256(value) * data.feeBps / 10_000;
        value -= uint256(feeAmount);

        // transfer fee
        if (feeAmount > 0) _transfer(auth.token, data.feeRecipient, feeAmount);

        // transfer payment
        if (value > 0) _transfer(auth.token, data.captureAddress, value);
    }

    /// @notice Return previously-captured tokens to buyer.
    /// @dev Reverts if not called by operator or captureAddress.
    function refund(uint256 value, bytes calldata paymentDetails) external nonZeroValue(value) {
        Authorization memory auth = abi.decode(paymentDetails, (Authorization));
        ExtraData memory data = auth.extraData;

        // check sender is operator or captureAddress
        if (msg.sender != data.operator && msg.sender != data.captureAddress) {
            revert InvalidRefundSender(msg.sender, data.operator, data.captureAddress);
        }

        // limit refund value to previously captured
        bytes32 paymentDetailsHash = keccak256(abi.encode(auth));
        uint256 captured = _captured[paymentDetailsHash];
        if (captured < value) revert RefundExceedsCapture(value, captured);

        _captured[paymentDetailsHash] = captured - value;
        emit Refunded(paymentDetailsHash, msg.sender, value);

        // return tokens to buyer
        SafeTransferLib.safeTransferFrom(auth.token, msg.sender, data.captureAddress, value);
    }

    /// TODO: consider refund liquidity provider i.e. reverse escrow payment
    /// stripe could sign a 3009 auth that will only be used for the refund intended by stripe
    /// operator can redeem 3009 to pull funds from stripe into escrow, and then atomically route to the buyer
    /// How to ensure that stripe's signed 3009 auth is actually used for a refund and not just used to buy something?

    /// Maybe stripe signs a 3009 auth for the refund, and then operator can redeem that 3009 auth to pull funds from stripe into escrow
    /// original paymentDetails hash for the original purchase could be hashed (twice) into the nonce that gets signed over (basically incompatible hash scheme)
    ///

    /// @notice Execute ERC3009 receiveWithAuthorization
    function _executeReceiveWithAuth(
        Authorization memory auth,
        uint256 value,
        bytes32 paymentDetailsHash,
        bytes calldata signature
    ) internal {
        bytes memory innerSignature = signature;
        if (signature.length >= 32 && bytes32(signature[signature.length - 32:]) == ERC6492_MAGIC_VALUE) {
            // Deploy smart wallet if needed. This version of PublicERC6492Validator does not include the final ecrecover
            // check, so will revert if validating an EOA signature. EOAs shouldn't provide 6492 sigs.
            // A possible TODO: Create new version of PublicERC6492Validator on Solady v0.1.0 that does include the final ecrecover.
            erc6492Validator.isValidSignatureNowAllowSideEffects(auth.from, paymentDetailsHash, signature);
            // If it's an ERC6492 signature, unwrap it to get the inner signature
            (,, innerSignature) = abi.decode(signature[0:signature.length - 32], (address, bytes, bytes));
        }

        IERC3009(auth.token).receiveWithAuthorization(
            auth.from, address(this), value, auth.validAfter, auth.validBefore, paymentDetailsHash, innerSignature
        );
    }

    /// @notice Validate fee configuration
    function _validateFees(uint16 feeBps, address feeRecipient) internal pure {
        if (feeBps > 10_000) revert FeeBpsOverflow(feeBps);
        if (feeRecipient == address(0) && feeBps != 0) revert ZeroFeeRecipient();
    }

    /// @notice Calculate and transfer fees
    function _handleFees(address token, address captureAddress, address feeRecipient, uint16 feeBps, uint256 value)
        internal
        returns (uint256 remainingValue)
    {
        uint256 feeAmount = uint256(value) * feeBps / 10_000;
        remainingValue = value - feeAmount;

        if (feeAmount > 0) _transfer(token, feeRecipient, feeAmount);
        if (remainingValue > 0) _transfer(token, captureAddress, remainingValue);
    }

    /// @notice Transfer tokens from the escrow to a recipient.
    function _transfer(address token, address recipient, uint256 value) internal {
        SafeTransferLib.safeTransfer(token, recipient, value);
    }
}
