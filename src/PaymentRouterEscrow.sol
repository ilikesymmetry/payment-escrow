// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {SpendPermission, SpendPermissionManager} from "spend-permissions/SpendPermissionManager.sol";

import {PaymentRouterBase} from "./PaymentRouterBase.sol";

/// @notice PaymentRouter with escrow functionality for improved capture guarantees.
contract PaymentRouterEscrow is PaymentRouterBase {
    error InsufficientEscrow(bytes32 permissionHash, uint256 escrowedValue, uint160 requestedValue);

    event Escrowed(bytes32 indexed permissionHash, uint256 value);

    event EscrowReleased(bytes32 indexed permissionHash, address recipient, uint256 value);

    mapping(bytes32 permissionHash => uint256 value) internal _escrowed;

    constructor(address initialOwner, SpendPermissionManager spendPermissionManager)
        PaymentRouterBase(initialOwner, spendPermissionManager)
    {}

    function escrow(SpendPermission calldata permission, uint160 value) external onlyOwner {
        PERMISSION_MANAGER.spend(permission, value);
        bytes32 permissionHash = PERMISSION_MANAGER.getHash(permission);
        _escrowed[permissionHash] += value;
        emit Escrowed(permissionHash, value);
    }

    function escrowWithSignature(SpendPermission calldata permission, uint160 value, bytes calldata signature)
        external
        onlyOwner
    {
        bool approved = PERMISSION_MANAGER.approveWithSignature(permission, signature);
        if (!approved) revert PermissionApprovalFailed();

        PERMISSION_MANAGER.spend(permission, value);

        bytes32 permissionHash = PERMISSION_MANAGER.getHash(permission);
        _escrowed[permissionHash] += value;
        emit Escrowed(permissionHash, value);
    }

    function captureFromEscrow(SpendPermission calldata permission, uint160 value) external onlyOwner {
        address recipient = decodeExtraData(permission.extraData);
        bytes32 permissionHash = PERMISSION_MANAGER.getHash(permission);
        uint256 escrowedValue = _escrowed[permissionHash];
        if (escrowedValue < value) revert InsufficientEscrow(permissionHash, escrowedValue, value);

        _escrowed[permissionHash] -= value;

        if (feeBps > 0) {
            _transfer(permission.token, feeRecipient, feeBps * value / 10_000);
        }
        _transfer(permission.token, decodeExtraData(permission.extraData), (10_000 - feeBps) * value / 10_000);

        emit EscrowReleased(permissionHash, recipient, value);
    }

    function void(SpendPermission calldata permission) external override onlyOwner {
        PERMISSION_MANAGER.revokeAsSpender(permission);

        bytes32 permissionHash = PERMISSION_MANAGER.getHash(permission);
        uint256 escrowedValue = _escrowed[permissionHash];
        if (escrowedValue == 0) return;

        delete _escrowed[permissionHash];
        _transfer(permission.token, permission.account, escrowedValue);
        emit EscrowReleased(permissionHash, permission.account, escrowedValue);
    }
}
