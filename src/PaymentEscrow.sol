// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";
import {IERC3009} from "./IERC3009.sol";
import {PublicERC6492Validator} from "spend-permissions/PublicERC6492Validator.sol";

/// @notice Route and escrow payments using ERC-3009 authorizations.
/// TODO: do we need to enforce a singular acceptable token address? (USDC)
contract PaymentEscrow {
    // Transient storage slots (cleared between transactions)
    // Using high slots to avoid collisions
    // Hardcoded slot values computed from keccak256("paymentescrow.current.*") - 1
    uint256 private constant TRANSIENT_SLOT_CURRENT_VALUE =
        0x3ea5c0ea4c9640f581a326aa37982451d2e0d8d4742013881665f1030d4850a0;
    uint256 private constant TRANSIENT_SLOT_CURRENT_TOKEN =
        0x47d4339d1052bb97c927a65e928f30d752743c0aad5ad858d770c3bb34b8b0a0;
    uint256 private constant TRANSIENT_SLOT_CURRENT_BUYER =
        0x8e04dc7c2a6b3d96835afd6439b6b1c5c2c7d0f0a68c2028258a1fb555c67a0c;
    uint256 private constant TRANSIENT_SLOT_CURRENT_DETAILS_HASH =
        0x5e0c167f292c73b1b22c3f38ad3eeac2c3bd15f1e25f4cf7e845a3e953d959d0;

    /// @notice Additional data to compliment ERC-3009 base fields
    struct ExtraData {
        uint256 salt;
        address operator;
        address merchant;
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
    error InvalidRefundSender(address sender, address operator, address merchant);
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

    /// @notice Transfers funds from buyer to merchant.
    function charge(uint256 value, bytes calldata paymentDetails, bytes calldata signature)
        external
        onlyOperator(paymentDetails)
    {
        Authorization memory auth = abi.decode(paymentDetails, (Authorization));
        ExtraData memory data = auth.extraData;

        // Set transient storage
        _setTransientCurrentValue(value);
        _setTransientCurrentToken(auth.token);
        _setTransientCurrentBuyer(auth.from);
        bytes32 paymentDetailsHash = keccak256(abi.encode(auth));
        _setTransientCurrentDetailsHash(paymentDetailsHash);

        _validateFees(data.feeBps, data.feeRecipient);
        _executeReceiveWithAuth(auth, value, paymentDetailsHash, signature);
        emit Charged(paymentDetailsHash, value);
        _handleFees(auth.token, data.merchant, data.feeRecipient, data.feeBps, value);

        // Clear transient storage
        _setTransientCurrentValue(0);
        _setTransientCurrentToken(address(0));
        _setTransientCurrentBuyer(address(0));
        _setTransientCurrentDetailsHash(bytes32(0));
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
        revert Unsupported(); // TODO: pretty sure we can implement this?
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

    /// @notice Cancel payment by revoking authorization and refunding all escrowed funds.
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
        _transfer(auth.token, data.merchant, authorizedValue); // TODO: shouldn't the recipient be the buyer?
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
        SafeTransferLib.safeTransferFrom(auth.token, msg.sender, data.merchant, value);
    }

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
    function _handleFees(address token, address merchant, address feeRecipient, uint16 feeBps, uint256 value)
        internal
        returns (uint256 remainingValue)
    {
        uint256 feeAmount = uint256(value) * feeBps / 10_000;
        remainingValue = value - feeAmount;

        if (feeAmount > 0) _transfer(token, feeRecipient, feeAmount);
        if (remainingValue > 0) _transfer(token, merchant, remainingValue);
    }

    /// @notice Transfer tokens from the escrow to a recipient.
    function _transfer(address token, address recipient, uint256 value) internal {
        SafeTransferLib.safeTransfer(token, recipient, value);
    }

    function _setTransientCurrentValue(uint256 value) internal {
        assembly {
            sstore(TRANSIENT_SLOT_CURRENT_VALUE, value)
        }
    }

    function _setTransientCurrentToken(address token) internal {
        assembly {
            sstore(TRANSIENT_SLOT_CURRENT_TOKEN, token)
        }
    }

    function _setTransientCurrentBuyer(address buyer) internal {
        assembly {
            sstore(TRANSIENT_SLOT_CURRENT_BUYER, buyer)
        }
    }

    function _setTransientCurrentDetailsHash(bytes32 detailsHash) internal {
        assembly {
            sstore(TRANSIENT_SLOT_CURRENT_DETAILS_HASH, detailsHash)
        }
    }

    function getCurrentValue() public view returns (uint256 value) {
        assembly {
            value := sload(TRANSIENT_SLOT_CURRENT_VALUE)
        }
    }

    function getCurrentToken() public view returns (address token) {
        assembly {
            token := sload(TRANSIENT_SLOT_CURRENT_TOKEN)
        }
    }

    function getCurrentBuyer() public view returns (address buyer) {
        assembly {
            buyer := sload(TRANSIENT_SLOT_CURRENT_BUYER)
        }
    }

    function getCurrentDetailsHash() public view returns (bytes32 detailsHash) {
        assembly {
            detailsHash := sload(TRANSIENT_SLOT_CURRENT_DETAILS_HASH)
        }
    }
}
