// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";
import {Ownable} from "solady/auth/Ownable.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SpendPermission, PeriodSpend, SpendPermissionManager} from "spend-permissions/SpendPermissionManager.sol";

/// @notice Route and escrow payments using Spend Permissions (https://github.com/coinbase/spend-permissions).
contract PaymentEscrow is Ownable {
    address public constant NATIVE_TOKEN = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    SpendPermissionManager public immutable PERMISSION_MANAGER;

    mapping(bytes32 permissionHash => uint256 value) internal _escrowed;
    mapping(bytes32 permissionhash => uint256 value) internal _captured;
    mapping(address operator => uint16 bps) _feeBps;
    mapping(address operator => address recipient) _feeRecipient;

    event PaymentEscrowed(bytes32 indexed permissionHash, uint256 value);
    event EscrowReduced(bytes32 indexed permissionHash, uint256 value);
    event PaymentCaptured(bytes32 indexed permissionHash, uint256 value);
    event PaymentRefunded(bytes32 indexed permissionHash, uint256 value);
    event FeesUpdated(address indexed operator, uint16 feeBps, address feeRecipient);

    error InsufficientEscrow(bytes32 permissionHash, uint256 escrowedValue, uint160 requestedValue);
    error PermissionApprovalFailed();
    error InvalidSender(address sender, address expected);
    error RefundExceedsCapture(uint256 refund, uint256 captured);
    error RefundValueMismatch(uint256 msgValue, uint256 argValue);
    error FeeBpsOverflow(uint16 feeBps);
    error ZeroFeeRecipient();

    modifier onlyOperator(SpendPermission calldata permission) {
        (address recipient, address operator) = decodeExtraData(permission.extraData);
        if (msg.sender != operator) revert InvalidSender(msg.sender, operator);
        _;
    }

    constructor(SpendPermissionManager spendPermissionManager) {
        PERMISSION_MANAGER = spendPermissionManager;
    }

    /// @notice Approve a spend permission via signature and enforce its approval status.
    function approve(spendPermission calldata permission, bytes calldata signature) external {
        bool approved = PERMISSION_MANAGER.approveWithSignature(permission, signature);
        if (!approved) revert PermissionApprovalFailed();
    }

    /// @notice Move funds from buyer to escrow via pre-approved spend permission.
    function escrow(SpendPermission calldata permission, uint160 value) external onlyOperator(permission) {
        PERMISSION_MANAGER.spend(permission, value);
        bytes32 permissionHash = PERMISSION_MANAGER.getHash(permission);
        _escrowed[permissionHash] += value;
        emit PaymentEscrowed(permissionHash, value);
    }

    /// @notice Move funds from escrow to buyer.
    /// @dev Intended for returning over-estimated taxes.
    function returnFromEscrow(SpendPermission calldata permission, uint160 value) external onlyOperator(permission) {
        bytes32 permissionHash = PERMISSION_MANAGER.getHash(permission);
        uint256 escrowedValue = _escrowed[permissionHash];
        if (escrowedValue < value) revert();

        _escrowed[permissionHash] -= value;
        emit EscrowReduced(permissionHash, escrowedValue);
        _transfer(permission.token, permission.account, value);
    }

    /// @notice Move funds from escrow to merchant.
    /// @dev Partial capture supported with custom value parameter.
    function captureFromEscrow(SpendPermission calldata permission, uint160 value) external onlyOperator(permission) {
        (address recipient, address operator) = decodeExtraData(permission.extraData);
        bytes32 permissionHash = PERMISSION_MANAGER.getHash(permission);
        uint256 escrowedValue = _escrowed[permissionHash];
        if (escrowedValue < value) revert InsufficientEscrow(permissionHash, escrowedValue, value);

        _escrowed[permissionHash] -= value;
        emit EscrowReduced(permissionHash, value);
        _capture(permissionHash, operator, recipient, permission.token, value);
    }

    /// @notice Move funds from buyer to merchant using a pre-approved spend permission.
    /// @dev Same net effect as batching escrow+captureFromEscrow but less effort.
    function capture(SpendPermission calldata permission, uint160 value) external onlyOperator(permission) {
        PERMISSION_MANAGER.spend(permission, value);

        bytes32 permissionHash = PERMISSION_MANAGER.getHash(permission);
        (address recipient, address operator) = decodeExtraData(permission.extraData);
        _capture(permissionHash, operator, recipient, permission.token, value);
    }

    /// @notice Return previously-captured tokens to buyer.
    function refund(SpendPermission calldata permission, uint160 value) external payable {
        // check sender is same as original payment recipient
        (address recipient,) = decodeExtraData(permission.extraData);
        if (msg.sender != recipient) revert InvalidSender(msg.sender, recipient);

        // limit refund value to previously captured
        bytes32 permissionHash = PERMISSION_MANAGER.getHash(permission);
        uint256 captured = _captured[permissionHash];
        if (captured < value) revert RefundExceedsCapture(value, captured);
        _captured[permissionHash] = captured - value;

        // return tokens to buyer
        if (permission.token == NATIVE_TOKEN) {
            if (value != msg.value) revert RefundValueMismatch(msg.value, value);
            SafeTransferLib.safeTransferETH(permission.account, value);
        } else {
            SafeTransferLib.safeTransferFrom(permission.token, recipient, permission.account, value);
        }

        emit PaymentRefunded(permissionHash, value);
    }

    /// @notice Cancel payment by revoking permission and returning escrowed funds.
    function void(SpendPermission calldata permission) external onlyOperator(permission) {
        PERMISSION_MANAGER.revokeAsSpender(permission);

        bytes32 permissionHash = PERMISSION_MANAGER.getHash(permission);
        uint256 escrowedValue = _escrowed[permissionHash];
        if (escrowedValue == 0) return;

        delete _escrowed[permissionHash];
        emit EscrowReduced(permissionHash, escrowedValue);
        _transfer(permission.token, permission.account, escrowedValue);
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
    function decodeExtraData(bytes calldata extraData) public pure returns (address recipient, address operator) {
        return abi.decode(extraData, (address, address));
    }

    /// @notice Transfer funds to payment receipient from this contract.
    function _capture(bytes32 permissionHash, address operator, address recipient, address token, uint256 value)
        internal
    {
        _captured[permissionHash] += value;

        uint16 feeBps = _feeBps[operator];
        if (feeBps > 0) {
            _transfer(token, _feeRecipient[operator], feeBps * value / 10_000);
        }
        _transfer(token, recipient, (10_000 - feeBps) * value / 10_000);

        emit PaymentCaptured(permissionHash, value);
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
