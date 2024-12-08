// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";
import {Ownable} from "solady/auth/Ownable.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SpendPermission, PeriodSpend, SpendPermissionManager} from "spend-permissions/SpendPermissionManager.sol";

contract PaymentRouter is Ownable {
    error FeeBpsOverflow(uint16 feeBps);

    error ZeroFeeRecipient();

    event FeesUpdated(uint16 feeBps, address feeRecipient);

    address public constant NATIVE_TOKEN = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    SpendPermissionManager public immutable PERMISSION_MANAGER;

    uint16 public feeBps;
    address public feeRecipient;

    constructor(address initialOwner, SpendPermissionManager spendPermissionManager) {
        _initializeOwner(initialOwner);
        PERMISSION_MANAGER = spendPermissionManager;
    }

    function capture(SpendPermission calldata permission, uint160 value) external onlyOwner {
        PERMISSION_MANAGER.spend(permission, value);

        if (feeBps > 0) {
            _transfer(permission.token, feeRecipient, feeBps * value / 10_000);
        }
        _transfer(permission.token, decodeExtraData(permission.extraData), (10_000 - feeBps) * value / 10_000);
    }

    function captureWithSignature(SpendPermission calldata permission, uint160 value, bytes calldata signature)
        external
        onlyOwner
    {
        PERMISSION_MANAGER.approveWithSignature(permission, signature);
        PERMISSION_MANAGER.spend(permission, value);

        if (feeBps > 0) {
            _transfer(permission.token, feeRecipient, feeBps * value / 10_000);
        }
        _transfer(permission.token, decodeExtraData(permission.extraData), (10_000 - feeBps) * value / 10_000);
    }

    function void(SpendPermission calldata permission) external virtual onlyOwner {
        PERMISSION_MANAGER.revokeAsSpender(permission);
    }

    function updateFees(uint16 newFeeBps, address newFeeRecipient) external onlyOwner {
        if (newFeeBps > 10_000) revert FeeBpsOverflow(newFeeBps);
        if (newFeeRecipient == address(0)) revert ZeroFeeRecipient();

        feeBps = newFeeBps;
        feeRecipient = newFeeRecipient;
        emit FeesUpdated(newFeeBps, newFeeRecipient);
    }

    function encodeExtraData(address recipient) public pure returns (bytes memory extraData) {
        return abi.encode(recipient);
    }

    function decodeExtraData(bytes calldata extraData) public pure returns (address recipient) {
        return abi.decode(extraData, (address));
    }

    function _transfer(address token, address recipient, uint256 value) internal {
        if (token == NATIVE_TOKEN) {
            SafeTransferLib.safeTransferETH(recipient, value);
        } else {
            SafeTransferLib.safeTransfer(token, recipient, value);
        }
    }
}
