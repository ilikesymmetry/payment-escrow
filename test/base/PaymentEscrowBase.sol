// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {PublicERC6492Validator} from "spend-permissions/PublicERC6492Validator.sol";
import {SpendPermissionManager} from "spend-permissions/SpendPermissionManager.sol";
import {CoinbaseSmartWallet} from "smart-wallet/CoinbaseSmartWallet.sol";
import {SpendPermissionManagerBase} from "spend-permissions/../test/base/SpendPermissionManagerBase.sol";
import {MockERC20} from "solady/../test/utils/mocks/MockERC20.sol";

import {PaymentEscrow} from "../../src/PaymentEscrow.sol";

contract PaymentEscrowBase is SpendPermissionManagerBase {
    PublicERC6492Validator publicERC6492Validator2;
    SpendPermissionManager spendPermissionManager;
    PaymentEscrow paymentEscrow;
    MockERC20 mockERC20;

    function _setUpPaymentEscrow() internal {
        _initializeSpendPermissionManager();
        publicERC6492Validator2 = new PublicERC6492Validator();
        spendPermissionManager = new SpendPermissionManager(publicERC6492Validator2, address(magicSpend));
        paymentEscrow = new PaymentEscrow(spendPermissionManager);
        mockERC20 = new MockERC20("mockERC20", "MOCK", 18);

        vm.prank(owner);
        account.addOwnerAddress(address(spendPermissionManager));
    }

    function _createPaymentSpendPermission(
        address token,
        uint160 value,
        address operator,
        address merchant,
        uint16 feeBps,
        address feeRecipient
    ) internal view returns (SpendPermissionManager.SpendPermission memory permission) {
        return SpendPermissionManager.SpendPermission({
            account: address(account),
            spender: address(paymentEscrow),
            token: token,
            start: uint48(vm.getBlockTimestamp()),
            end: type(uint48).max,
            period: type(uint48).max,
            allowance: value,
            salt: 0,
            extraData: abi.encode(operator, merchant, feeBps, feeRecipient)
        });
    }

    function _signPaymentSpendPermission(SpendPermissionManager.SpendPermission memory permission)
        internal
        view
        returns (bytes memory)
    {
        bytes32 permissionHash = spendPermissionManager.getHash(permission);
        bytes32 replaySafeHash = CoinbaseSmartWallet(payable(permission.account)).replaySafeHash(permissionHash);
        bytes memory signature = _sign(ownerPk, replaySafeHash);
        bytes memory wrappedSignature = _applySignatureWrapper(0, signature);
        return wrappedSignature;
    }
}
