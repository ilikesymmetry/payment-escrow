// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {PaymentEscrowSmartWalletWithMagicSpendBase} from "../../base/PaymentEscrowSmartWalletWithMagicSpendBase.sol";
import {PaymentEscrow} from "../../../src/PaymentEscrow.sol";

contract PaymentEscrowMagicSpendE2ETest is PaymentEscrowSmartWalletWithMagicSpendBase {
    function test_charge_succeeds_withMagicSpend() public {
        uint256 amount = 100e6;
        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 days;

        // Make sure smart wallet has no tokens
        assertEq(mockERC3009Token.balanceOf(address(smartWalletDeployed)), 0);

        // But make sure magic spend has enough tokens to fulfill the withdraw
        mockERC3009Token.mint(address(magicSpend), amount);

        // Create payment details
        PaymentEscrow.Authorization memory auth = PaymentEscrow.Authorization({
            token: address(mockERC3009Token),
            from: address(smartWalletDeployed),
            to: address(paymentEscrow),
            validAfter: validAfter,
            validBefore: validBefore,
            extraData: PaymentEscrow.ExtraData({
                salt: uint256(0),
                operator: operator,
                merchant: merchant,
                feeBps: FEE_BPS,
                feeRecipient: feeRecipient
            })
        });
        bytes memory paymentDetails = abi.encode(auth);

        // Create signature that includes magic spend withdraw
        bytes memory signature = _signSmartWalletERC3009WithMagicSpend(
            address(smartWalletDeployed),
            address(paymentEscrow),
            amount,
            auth.validAfter,
            auth.validBefore,
            DEPLOYED_WALLET_OWNER_PK,
            0,
            0 // nonceEntropy
        );

        // Submit charge
        vm.prank(operator);
        paymentEscrow.charge(amount, paymentDetails, signature);

        // Verify final balances
        uint256 feeAmount = amount * FEE_BPS / 10_000;
        assertEq(mockERC3009Token.balanceOf(merchant), amount - feeAmount);
        assertEq(mockERC3009Token.balanceOf(feeRecipient), feeAmount);
        assertEq(mockERC3009Token.balanceOf(address(magicSpend)), 0);
        assertEq(mockERC3009Token.balanceOf(address(smartWalletDeployed)), 0);
    }
}
