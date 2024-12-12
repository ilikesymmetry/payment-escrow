// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";
import {Ownable} from "solady/auth/Ownable.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SpendPermission, PeriodSpend, SpendPermissionManager} from "spend-permissions/SpendPermissionManager.sol";

/**
 * TODO
 * refund function
 * per-transaction fee take rate and recipients
 */

/// @notice Route payments to recipients using Spend Permissions (https://github.com/coinbase/spend-permissions).
contract PaymentRouterBase is Ownable {
    event EscrowIncreased(bytes32 indexed permissionHash, address indexed account, uint256 value);

    event EscrowDecreased(bytes32 indexed permissionHash, address indexed account, uint256 value);

    event EscrowCaptured(bytes32 indexed permissionHash, address recipient, uint256 value);

    event FeesUpdated(address indexed operator, uint16 feeBps, address feeRecipient);

    error InsufficientEscrow(bytes32 permissionHash, uint256 escrowedValue, uint160 requestedValue);

    error PermissionApprovalFailed();

    error FeeBpsOverflow(uint16 feeBps);

    error ZeroFeeRecipient();

    address public constant NATIVE_TOKEN = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    SpendPermissionManager public immutable PERMISSION_MANAGER;

    mapping(bytes32 permissionHash => uint256 value) internal _escrowed;

    mapping(address operator => uint16 bps) _feeBps;

    mapping(address operator => address recipient) _feeRecipient;

    modifier onlyOperator(SpendPermission calldata permission) {
        (address recipient, address operator) = decodeExtraData(permission.extraData);
        if (msg.sender != operator) revert();
        _;
    }

    constructor(SpendPermissionManager spendPermissionManager) {
        PERMISSION_MANAGER = spendPermissionManager;
    }

    /// @notice Move funds from buyer to escrow via a signed spend permission.
    function escrowWithSignature(SpendPermission calldata permission, uint160 value, bytes calldata signature)
        external
        onlyOperator(permission)
    {
        bool approved = PERMISSION_MANAGER.approveWithSignature(permission, signature);
        if (!approved) revert PermissionApprovalFailed();

        PERMISSION_MANAGER.spend(permission, value);

        bytes32 permissionHash = PERMISSION_MANAGER.getHash(permission);
        _escrowed[permissionHash] += value;
        emit EscrowIncreased(permissionHash, permission.account, value);
    }

    /// @notice Move funds from buyer to escrow via pre-approved spend permission.
    function escrow(SpendPermission calldata permission, uint160 value) external onlyOperator(permission) {
        PERMISSION_MANAGER.spend(permission, value);
        bytes32 permissionHash = PERMISSION_MANAGER.getHash(permission);
        _escrowed[permissionHash] += value;
        emit EscrowIncreased(permissionHash, permission.account, value);
    }

    /// @notice Move funds from escrow to buyer.
    /// @dev Intended for returning over-estimated taxes.
    function revertEscrow(SpendPermission calldata permission, uint160 value) external onlyOperator(permission) {
        bytes32 permissionHash = PERMISSION_MANAGER.getHash(permission);
        uint256 escrowedValue = _escrowed[permissionHash];
        if (escrowedValue < value) revert();

        _escrowed[permissionHash] -= value;
        _transfer(permission.token, permission.account, value);
        emit EscrowDecreased(permissionHash, permission.account, escrowedValue);
    }

    /// @notice Move funds from escrow to merchant.
    /// @dev Partial capture supported with custom value parameter.
    function captureFromEscrow(SpendPermission calldata permission, uint160 value) external onlyOperator(permission) {
        (address recipient, address operator) = decodeExtraData(permission.extraData);
        bytes32 permissionHash = PERMISSION_MANAGER.getHash(permission);
        uint256 escrowedValue = _escrowed[permissionHash];
        if (escrowedValue < value) revert InsufficientEscrow(permissionHash, escrowedValue, value);

        _escrowed[permissionHash] -= value;

        uint16 feeBps = _feeBps[operator];
        if (feeBps > 0) {
            _transfer(permission.token, _feeRecipient[operator], feeBps * value / 10_000);
        }
        _transfer(permission.token, recipient, (10_000 - feeBps) * value / 10_000);

        emit EscrowCaptured(permissionHash, recipient, value);
    }

    /// @notice Cancel payment by revoking permission and returning escrowed funds.
    function void(SpendPermission calldata permission) external onlyOperator(permission) {
        PERMISSION_MANAGER.revokeAsSpender(permission);

        bytes32 permissionHash = PERMISSION_MANAGER.getHash(permission);
        uint256 escrowedValue = _escrowed[permissionHash];
        if (escrowedValue == 0) return;

        delete _escrowed[permissionHash];
        _transfer(permission.token, permission.account, escrowedValue);
        emit EscrowDecreased(permissionHash, permission.account, escrowedValue);
    }

    /// @notice Pull funds from merchant and return to buyer.
    function refund(SpendPermission calldata permission, uint160 value) external onlyOperator(permission) {
        // TODO
    }

    // IMMEDIATE CAPTURE

    /// @notice Move funds from buyer to merchant using a pre-approved spend permission.
    function capture(SpendPermission calldata permission, uint160 value) external onlyOperator(permission) {
        (address recipient, address operator) = decodeExtraData(permission.extraData);
        PERMISSION_MANAGER.spend(permission, value);

        uint16 feeBps = _feeBps[operator];
        if (feeBps > 0) {
            _transfer(permission.token, operator, feeBps * value / 10_000);
        }
        _transfer(permission.token, recipient, (10_000 - feeBps) * value / 10_000);
    }

    /// @notice Move funds from buyer to merchant while approving a spend permission.
    function captureWithSignature(SpendPermission calldata permission, uint160 value, bytes calldata signature)
        external
        onlyOperator(permission)
    {
        bool approved = PERMISSION_MANAGER.approveWithSignature(permission, signature);
        if (!approved) revert PermissionApprovalFailed();

        PERMISSION_MANAGER.spend(permission, value);

        (address recipient, address operator) = decodeExtraData(permission.extraData);
        uint16 feeBps = _feeBps[operator];
        if (feeBps > 0) {
            _transfer(permission.token, operator, feeBps * value / 10_000);
        }
        _transfer(permission.token, recipient, (10_000 - feeBps) * value / 10_000);
    }

    /// @notice Update fee take rate and recipient for operator.
    function updateFees(uint16 newFeeBps, address newFeeRecipient) external {
        if (newFeeBps > 10_000) revert FeeBpsOverflow(newFeeBps);
        if (newFeeRecipient == address(0)) revert ZeroFeeRecipient();

        _feeBps[msg.sender] = newFeeBps;
        _feeRecipient[msg.sender] = newFeeRecipient;
        emit FeesUpdated(msg.sender, newFeeBps, newFeeRecipient);
    }

    function encodeExtraData(address recipient, address operator) public pure returns (bytes memory extraData) {
        return abi.encode(recipient, operator);
    }

    function decodeExtraData(bytes calldata extraData) public pure returns (address recipient, address operator) {
        return abi.decode(extraData, (address, address));
    }

    function _transfer(address token, address recipient, uint256 value) internal {
        if (token == NATIVE_TOKEN) {
            SafeTransferLib.safeTransferETH(recipient, value);
        } else {
            SafeTransferLib.safeTransfer(token, recipient, value);
        }
    }
}
