// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

/// @notice Route and escrow payments using ERC-3009 authorizations.
interface IPaymentEscrow {
    /// @notice ERC-3009 authorization
    struct Authorization {
        address token;
        address from;
        address to;
        uint256 validAfter;
        uint256 validBefore;
        ExtraData extraData;
    }

    /// @notice Additional data to compliment ERC-3009 base fields
    struct ExtraData {
        uint256 salt;
        address operator;
        address merchant;
        uint16 feeBps;
        address feeRecipient;
    }

    /// @notice Payment charged to buyer and immediately captured.
    event Charged(bytes32 indexed paymentDetailsHash, uint256 value);

    /// @notice Payment authorized, increasing value escrowed.
    event AuthorizationIncreased(bytes32 indexed paymentDetailsHash, uint256 value);

    /// @notice Payment refunded to buyer, descreasing value escrowed.
    event AuthorizationVoided(bytes32 indexed paymentDetailsHash);

    /// @notice Payment captured, descreasing value escrowed.
    event AuthorizationCaptured(bytes32 indexed paymentDetailsHash, uint256 value);

    /// @notice Payment refunded to buyer.
    event Refunded(bytes32 indexed paymentDetailsHash, address indexed refunder, uint256 value);

    /// @notice Transfers funds from buyer to merchant.
    /// @dev Reverts if not called by operator.
    function charge(uint256 value, bytes calldata paymentDetails, bytes calldata signature) external;

    /// @notice Validates buyer signature and transfers funds from buyer to escrow.
    /// @dev Reverts if not called by operator.
    function confirmAuthorization(uint256 value, bytes calldata paymentDetails, bytes calldata signature) external;

    /// @notice Cancel payment by revoking authorization and refunding all escrowed funds.
    /// @dev Reverts if not called by operator or merchant.
    function voidAuthorization(bytes calldata paymentDetails) external;

    /// @notice Transfer previously-escrowed funds to merchant.
    /// @dev Reverts if not called by operator.
    /// @dev Partial capture with custom value parameter and calling multiple times.
    function captureAuthorization(uint256 value, bytes calldata paymentDetails) external;

    /// @notice Return previously-captured tokens to buyer.
    /// @dev Reverts if not called by operator or merchant.
    function refund(uint256 value, bytes calldata paymentDetails) external;
}
