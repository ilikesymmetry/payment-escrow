// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";
import {IERC3009} from "./IERC3009.sol";
import {console2} from "forge-std/console2.sol";
import {PublicERC6492Validator} from "./PublicERC6492Validator.sol";

/// @notice Route and escrow payments using Spend Permissions (https://github.com/coinbase/spend-permissions).
contract PaymentEscrow {
    /// @notice ERC-7528 native token address
    address public constant NATIVE_TOKEN = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    /// @notice Additional data to compliment ERC-3009 base fields
    struct ExtraData {
        uint256 salt;
        address operator;
        address merchant;
        uint16 feeBps;
        address feeRecipient;
    }

    struct Authorization {
        address token;
        address from;
        address to;
        uint256 validAfter;
        uint256 validBefore;
        ExtraData extraData;
    }

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
    event AuthorizationVoided(bytes32 indexed paymentDetailsHash);

    /// @notice Payment captured, descreasing value escrowed.
    event AuthorizationCaptured(bytes32 indexed paymentDetailsHash, uint256 value);

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
    error Unsupported();
    error InvalidSignature();

    PublicERC6492Validator public immutable erc6492Validator;

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

    /// @notice Execute ERC3009 receiveWithAuthorization
    function _executeReceiveWithAuth(
        Authorization memory auth,
        uint256 value,
        bytes32 paymentDetailsHash,
        bytes calldata signature
    ) internal {
        // First validate signature, deploying smart wallet if needed
        console2.log("About to validate signature for hash:", uint256(paymentDetailsHash));
        // if (!erc6492Validator.isValidSignatureNowAllowSideEffects(auth.from, paymentDetailsHash, signature)) {
        //     // If 6492 validation fails, we know it's not a valid signature
        //     revert InvalidSignature();
        // }
        console2.log("skipping ERC6492 stuff");
        // If signature is valid (either EOA or smart wallet), execute the transfer
        IERC3009(auth.token).receiveWithAuthorization(
            auth.from, auth.to, value, auth.validAfter, auth.validBefore, paymentDetailsHash, signature
        );
    }

    /// @notice Validate fee configuration
    function _validateFees(uint16 feeBps, address feeRecipient) internal pure {
        if (feeBps > 10_000) revert FeeBpsOverflow(feeBps);
        if (feeRecipient == address(0) && feeBps != 0) revert ZeroFeeRecipient();
    }

    /// @notice Calculate and transfer fees
    function _handleFees(address token, address merchant, address feeRecipient, uint16 feeBps, uint256 value)
        internal
        returns (uint256 remainingValue)
    {
        uint256 feeAmount = uint256(value) * feeBps / 10_000;
        remainingValue = value - feeAmount;

        if (feeAmount > 0) _transfer(token, feeRecipient, feeAmount);
        if (remainingValue > 0) _transfer(token, merchant, remainingValue);
    }

    /// @notice Transfers funds from buyer to merchant.
    function charge(uint256 value, bytes calldata paymentDetails, bytes calldata signature)
        external
        onlyOperator(paymentDetails)
    {
        Authorization memory auth = abi.decode(paymentDetails, (Authorization));
        ExtraData memory data = auth.extraData;

        _validateFees(data.feeBps, data.feeRecipient);

        bytes32 paymentDetailsHash = keccak256(abi.encode(auth));
        console2.log("PaymentEscrow paymentDetailsHash:", uint256(paymentDetailsHash));

        _executeReceiveWithAuth(auth, value, paymentDetailsHash, signature);
        emit Charged(paymentDetailsHash, value);

        _handleFees(auth.token, data.merchant, data.feeRecipient, data.feeBps, value);
    }

    /// @notice Validates buyer signature and transfers funds from buyer to escrow.
    /// @dev Reverts if not called by operator.
    function confirmAuthorization(uint256 value, bytes calldata paymentDetails, bytes calldata signature)
        external
        onlyOperator(paymentDetails)
        nonZeroValue(value)
    {
        Authorization memory auth = abi.decode(paymentDetails, (Authorization));
        ExtraData memory data = auth.extraData;

        _validateFees(data.feeBps, data.feeRecipient);

        bytes32 paymentDetailsHash = keccak256(abi.encode(auth));
        _executeReceiveWithAuth(auth, value, paymentDetailsHash, signature);

        _authorized[paymentDetailsHash] += value;
        emit AuthorizationIncreased(paymentDetailsHash, value);
    }

    /// @notice Transfer funds from buyer to escrow via pre-approved SpendPermission.
    /// @dev Reverts if not called by operator.
    function increaseAuthorization(uint256 value, bytes calldata paymentDetails)
        external
        onlyOperator(paymentDetails)
        nonZeroValue(value)
    {
        revert Unsupported();
    }

    /// @notice Return previously-escrowed funds to buyer.
    /// @dev Reverts if not called by operator or merchant.
    function decreaseAuthorization(uint256 value, bytes calldata paymentDetails)
        external
        onlyOperator(paymentDetails)
        nonZeroValue(value)
    {
        Authorization memory auth = abi.decode(paymentDetails, (Authorization));
        ExtraData memory data = auth.extraData;
        bytes32 paymentDetailsHash = keccak256(abi.encode(auth));

        // check sufficient authorization
        uint256 authorizedValue = _authorized[paymentDetailsHash];
        if (authorizedValue < value) revert InsufficientAuthorization(paymentDetailsHash, authorizedValue, value);

        _authorized[paymentDetailsHash] = authorizedValue - value;
        emit AuthorizationDecreased(paymentDetailsHash, value);
        _transfer(auth.token, data.merchant, value);
    }

    /// @notice Cancel payment by revoking permission and refunding all escrowed funds.
    /// @dev Reverts if not called by operator or merchant.
    function voidAuthorization(bytes calldata paymentDetails) external onlyOperator(paymentDetails) {
        Authorization memory auth = abi.decode(paymentDetails, (Authorization));
        ExtraData memory data = auth.extraData;
        bytes32 paymentDetailsHash = keccak256(abi.encode(auth));

        // TODO: revoke authorization

        // early return if no authorized value
        uint256 authorizedValue = _authorized[paymentDetailsHash];
        if (authorizedValue == 0) return;

        delete _authorized[paymentDetailsHash];
        emit AuthorizationDecreased(paymentDetailsHash, authorizedValue);
        emit AuthorizationVoided(paymentDetailsHash);
        _transfer(auth.token, data.merchant, authorizedValue);
    }

    /// @notice Transfer previously-escrowed funds to merchant.
    /// @dev Reverts if not called by operator.
    /// @dev Partial capture with custom value parameter and calling multiple times.
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
        if (value > 0) _transfer(auth.token, data.merchant, value);
    }

    /// @notice Return previously-captured tokens to buyer.
    /// @dev Reverts if not called by operator or merchant.
    function refund(uint256 value, bytes calldata paymentDetails) external payable nonZeroValue(value) {
        Authorization memory auth = abi.decode(paymentDetails, (Authorization));
        ExtraData memory data = auth.extraData;

        // check sender is operator or merchant
        if (msg.sender != data.operator && msg.sender != data.merchant) {
            revert InvalidRefundSender(msg.sender, data.operator, data.merchant);
        }

        // limit refund value to previously captured
        bytes32 paymentDetailsHash = keccak256(abi.encode(auth));
        uint256 captured = _captured[paymentDetailsHash];
        if (captured < value) revert RefundExceedsCapture(value, captured);

        _captured[paymentDetailsHash] = captured - value;
        emit Refunded(paymentDetailsHash, msg.sender, value);

        // return tokens to buyer
        if (auth.token == NATIVE_TOKEN) {
            if (value != msg.value) revert NativeTokenValueMismatch(msg.value, value);
            SafeTransferLib.safeTransferETH(data.merchant, value);
        } else {
            SafeTransferLib.safeTransferFrom(auth.token, msg.sender, data.merchant, value);
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
