// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {PaymentEscrow} from "../../../src/PaymentEscrow.sol";
import {PaymentEscrowBase} from "../../base/PaymentEscrowBase.sol";
import {PaymentEscrowSmartWalletBase} from "../../base/PaymentEscrowSmartWalletBase.sol";
import {console2} from "forge-std/console2.sol";

contract PaymentEscrowE2ETest is PaymentEscrowBase {
    function test_charge() public {
        uint256 amount = 100e6;
        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 days;

        // Create payment details first
        PaymentEscrow.Authorization memory auth = PaymentEscrow.Authorization({
            token: address(token),
            from: buyer,
            to: address(paymentEscrow),
            validAfter: validAfter,
            validBefore: validBefore,
            extraData: PaymentEscrow.ExtraData({
                salt: 0, // Keep salt as 0
                operator: operator,
                merchant: merchant,
                feeBps: FEE_BPS,
                feeRecipient: feeRecipient
            })
        });

        bytes memory paymentDetails = abi.encode(auth);
        bytes32 nonce = keccak256(paymentDetails); // Use paymentDetailsHash as nonce
        console2.log("Test nonce:", uint256(nonce));

        bytes memory signature =
            _signERC3009(buyer, address(paymentEscrow), amount, validAfter, validBefore, nonce, BUYER_PK);

        vm.prank(operator);
        paymentEscrow.charge(amount, paymentDetails, signature);

        uint256 feeAmount = amount * FEE_BPS / 10_000;
        assertEq(token.balanceOf(merchant), amount - feeAmount);
        assertEq(token.balanceOf(feeRecipient), feeAmount);
    }
}

contract PaymentEscrowSmartWalletE2ETest is PaymentEscrowSmartWalletBase {
    function test_charge_with_smart_wallet() public {
        // Create payment details
        (uint256 validAfter, uint256 validBefore) = _getValidTimeRange();
        bytes memory paymentDetails = _createSmartWalletPaymentDetails(100e6, validAfter, validBefore, bytes32(0));
        bytes32 nonce = keccak256(paymentDetails); // Use paymentDetailsHash as nonce
        console2.log("Payment details hash:", uint256(keccak256(paymentDetails)));

        // Create signature
        bytes memory signature = _signSmartWalletERC3009(
            smartWalletBuyer, address(paymentEscrow), 100e6, validAfter, validBefore, nonce, SMART_WALLET_OWNER_PK, 0
        );

        // Submit charge
        vm.prank(operator);
        uint256 amount = 100e6;
        paymentEscrow.charge(amount, paymentDetails, signature);

        uint256 feeAmount = amount * FEE_BPS / 10_000;
        assertEq(token.balanceOf(merchant), amount - feeAmount);
        assertEq(token.balanceOf(feeRecipient), feeAmount);
    }
}
