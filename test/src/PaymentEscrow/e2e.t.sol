// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {PaymentEscrow} from "../../../src/PaymentEscrow.sol";
import {PaymentEscrowBase} from "../../base/PaymentEscrowBase.sol";
import {PaymentEscrowSmartWalletBase} from "../../base/PaymentEscrowSmartWalletBase.sol";

contract PaymentEscrowE2ETest is PaymentEscrowBase {
    function test_charge_succeeds_withEOA() public {
        uint256 amount = 100e6;
        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 days;

        // Create payment details first
        PaymentEscrow.Authorization memory auth = PaymentEscrow.Authorization({
            token: address(mockERC3009Token),
            from: buyerEOA,
            to: address(paymentEscrow),
            validAfter: validAfter,
            validBefore: validBefore,
            value: amount,
            extraData: PaymentEscrow.ExtraData({
                salt: 0, // Keep salt as 0
                operator: operator,
                captureAddress: captureAddress,
                feeBps: FEE_BPS,
                feeRecipient: feeRecipient
            })
        });

        bytes memory paymentDetails = abi.encode(auth);
        bytes32 nonce = keccak256(paymentDetails); // Use paymentDetailsHash as nonce

        bytes memory signature =
            _signERC3009(buyerEOA, address(paymentEscrow), amount, validAfter, validBefore, nonce, BUYER_EOA_PK);

        vm.prank(operator);
        paymentEscrow.charge(amount, paymentDetails, signature);

        uint256 feeAmount = amount * FEE_BPS / 10_000;
        assertEq(mockERC3009Token.balanceOf(captureAddress), amount - feeAmount);
        assertEq(mockERC3009Token.balanceOf(feeRecipient), feeAmount);
    }
}

contract PaymentEscrowSmartWalletE2ETest is PaymentEscrowSmartWalletBase {
    function test_charge_succeeds_withDeployedSmartWallet() public {
        // Create payment details
        PaymentEscrow.Authorization memory auth = PaymentEscrow.Authorization({
            token: address(mockERC3009Token),
            from: address(smartWalletDeployed),
            to: address(paymentEscrow),
            validAfter: block.timestamp - 1,
            validBefore: block.timestamp + 1 days,
            value: 100e6,
            extraData: PaymentEscrow.ExtraData({
                salt: uint256(0),
                operator: operator,
                captureAddress: captureAddress,
                feeBps: FEE_BPS,
                feeRecipient: feeRecipient
            })
        });
        bytes memory paymentDetails = abi.encode(auth);
        // bytes32 nonce = keccak256(paymentDetails); // Use paymentDetailsHash as nonce

        // Create signature
        bytes memory signature = _signSmartWalletERC3009(
            address(smartWalletDeployed),
            address(paymentEscrow),
            100e6,
            auth.validAfter,
            auth.validBefore,
            DEPLOYED_WALLET_OWNER_PK,
            0
        );

        // Submit charge
        vm.prank(operator);
        uint256 amount = 100e6;
        paymentEscrow.charge(amount, paymentDetails, signature);

        uint256 feeAmount = amount * FEE_BPS / 10_000;
        assertEq(mockERC3009Token.balanceOf(captureAddress), amount - feeAmount);
        assertEq(mockERC3009Token.balanceOf(feeRecipient), feeAmount);
    }

    function test_charge_succeeds_withCounterfactualSmartWallet() public {
        // Create payment details
        PaymentEscrow.Authorization memory auth = PaymentEscrow.Authorization({
            token: address(mockERC3009Token),
            from: address(smartWalletCounterfactual),
            to: address(paymentEscrow),
            validAfter: block.timestamp - 1,
            validBefore: block.timestamp + 1 days,
            value: 100e6,
            extraData: PaymentEscrow.ExtraData({
                salt: uint256(0),
                operator: operator,
                captureAddress: captureAddress,
                feeBps: FEE_BPS,
                feeRecipient: feeRecipient
            })
        });
        bytes memory paymentDetails = abi.encode(auth);
        // bytes32 nonce = keccak256(paymentDetails); // Use paymentDetailsHash as nonce

        // Create signature
        bytes memory signature = _signSmartWalletERC3009WithERC6492(
            address(smartWalletCounterfactual),
            address(paymentEscrow),
            100e6,
            auth.validAfter,
            auth.validBefore,
            COUNTERFACTUAL_WALLET_OWNER_PK,
            0
        );

        // Submit charge
        vm.prank(operator);
        uint256 amount = 100e6;
        paymentEscrow.charge(amount, paymentDetails, signature);

        uint256 feeAmount = amount * FEE_BPS / 10_000;
        assertEq(mockERC3009Token.balanceOf(captureAddress), amount - feeAmount);
        assertEq(mockERC3009Token.balanceOf(feeRecipient), feeAmount);
    }
}
