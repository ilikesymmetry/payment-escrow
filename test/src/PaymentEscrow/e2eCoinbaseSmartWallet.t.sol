// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {PaymentEscrow} from "../../../src/PaymentEscrow.sol";
import {PaymentEscrowBase} from "../../base/PaymentEscrowBase.sol";
import {PaymentEscrowSmartWalletBase} from "../../base/PaymentEscrowSmartWalletBase.sol";

contract PaymentEscrowSmartWalletE2ETest is PaymentEscrowSmartWalletBase {
    function test_charge_succeeds_withDeployedSmartWallet(uint256 amount) public {
        // Get wallet's current balance
        uint256 walletBalance = mockERC3009Token.balanceOf(address(smartWalletDeployed));

        // Assume reasonable values
        vm.assume(amount > 0 && amount <= walletBalance);

        // Create payment details
        PaymentEscrow.Authorization memory auth = PaymentEscrow.Authorization({
            token: address(mockERC3009Token),
            buyer: address(smartWalletDeployed),
            validAfter: block.timestamp - 1,
            validBefore: block.timestamp + 1 days,
            value: amount,
            operator: operator,
            captureAddress: captureAddress,
            feeBps: FEE_BPS,
            feeRecipient: feeRecipient,
            salt: uint256(0)
        });
        bytes memory paymentDetails = abi.encode(auth);
        // bytes32 nonce = keccak256(paymentDetails); // Use paymentDetailsHash as nonce

        // Create signature
        bytes memory signature = _signSmartWalletERC3009(
            address(smartWalletDeployed),
            captureAddress,
            amount,
            auth.validAfter,
            auth.validBefore,
            DEPLOYED_WALLET_OWNER_PK,
            0
        );

        // Submit charge
        vm.prank(operator);
        paymentEscrow.charge(amount, paymentDetails, signature);

        uint256 feeAmount = amount * FEE_BPS / 10_000;
        assertEq(mockERC3009Token.balanceOf(captureAddress), amount - feeAmount);
        assertEq(mockERC3009Token.balanceOf(feeRecipient), feeAmount);
    }

    function test_charge_succeeds_withCounterfactualSmartWallet(uint256 amount) public {
        // Get wallet's current balance
        uint256 walletBalance = mockERC3009Token.balanceOf(address(smartWalletCounterfactual));

        // Assume reasonable values
        vm.assume(amount > 0 && amount <= walletBalance);

        // Verify smart wallet is not deployed yet
        address wallet = address(smartWalletCounterfactual);
        assertEq(wallet.code.length, 0, "Smart wallet should not be deployed yet");

        // Create payment details
        PaymentEscrow.Authorization memory auth = PaymentEscrow.Authorization({
            token: address(mockERC3009Token),
            buyer: address(smartWalletCounterfactual),
            validAfter: block.timestamp - 1,
            validBefore: block.timestamp + 1 days,
            value: amount,
            operator: operator,
            captureAddress: captureAddress,
            feeBps: FEE_BPS,
            feeRecipient: feeRecipient,
            salt: uint256(0)
        });
        bytes memory paymentDetails = abi.encode(auth);
        // bytes32 nonce = keccak256(paymentDetails); // Use paymentDetailsHash as nonce

        // Create signature
        bytes memory signature = _signSmartWalletERC3009WithERC6492(
            address(smartWalletCounterfactual),
            captureAddress,
            amount,
            auth.validAfter,
            auth.validBefore,
            COUNTERFACTUAL_WALLET_OWNER_PK,
            0
        );

        // Submit charge
        vm.prank(operator);
        paymentEscrow.charge(amount, paymentDetails, signature);

        uint256 feeAmount = amount * FEE_BPS / 10_000;
        assertEq(mockERC3009Token.balanceOf(captureAddress), amount - feeAmount);
        assertEq(mockERC3009Token.balanceOf(feeRecipient), feeAmount);
    }
}
