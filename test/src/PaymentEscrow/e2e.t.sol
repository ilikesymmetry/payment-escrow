// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {PaymentEscrowBase} from "../../base/PaymentEscrowBase.sol";
import {PaymentEscrow} from "../../../src/PaymentEscrow.sol";
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
