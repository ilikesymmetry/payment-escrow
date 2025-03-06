// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {PaymentEscrow} from "../../../src/PaymentEscrow.sol";
import {PaymentEscrowBase} from "../../base/PaymentEscrowBase.sol";

contract ChargeTest is PaymentEscrowBase {
    function test_charge_succeeds_whenValueEqualsAuthorized(uint256 amount) public {
        uint256 buyerBalance = mockERC3009Token.balanceOf(buyerEOA);

        vm.assume(amount > 0 && amount <= buyerBalance);

        PaymentEscrow.Authorization memory auth = PaymentEscrow.Authorization({
            token: address(mockERC3009Token),
            buyer: buyerEOA,
            validAfter: block.timestamp - 1,
            validBefore: block.timestamp + 1 days,
            value: amount,
            operator: operator,
            captureAddress: captureAddress,
            feeBps: FEE_BPS,
            feeRecipient: feeRecipient,
            salt: 0
        });

        bytes memory paymentDetails = abi.encode(auth);
        bytes32 paymentDetailsHash = keccak256(paymentDetails);

        bytes memory signature = _signERC3009(
            buyerEOA,
            address(paymentEscrow),
            amount,
            auth.validAfter,
            auth.validBefore,
            paymentDetailsHash,
            BUYER_EOA_PK
        );

        uint256 buyerBalanceBefore = mockERC3009Token.balanceOf(buyerEOA);

        vm.prank(operator);
        paymentEscrow.charge(amount, paymentDetails, signature);

        uint256 feeAmount = amount * FEE_BPS / 10_000;
        assertEq(mockERC3009Token.balanceOf(captureAddress), amount - feeAmount);
        assertEq(mockERC3009Token.balanceOf(feeRecipient), feeAmount);
        assertEq(mockERC3009Token.balanceOf(buyerEOA), buyerBalanceBefore - amount);
    }

    function test_charge_succeeds_whenValueLessThanAuthorized(uint256 authorizedAmount, uint256 chargeAmount) public {
        uint256 buyerBalance = mockERC3009Token.balanceOf(buyerEOA);

        vm.assume(authorizedAmount > 0 && authorizedAmount <= buyerBalance);
        vm.assume(chargeAmount > 0 && chargeAmount < authorizedAmount);

        PaymentEscrow.Authorization memory auth = PaymentEscrow.Authorization({
            token: address(mockERC3009Token),
            buyer: buyerEOA,
            validAfter: block.timestamp - 1,
            validBefore: block.timestamp + 1 days,
            value: authorizedAmount,
            operator: operator,
            captureAddress: captureAddress,
            feeBps: FEE_BPS,
            feeRecipient: feeRecipient,
            salt: 0
        });

        bytes memory paymentDetails = abi.encode(auth);
        bytes32 paymentDetailsHash = keccak256(paymentDetails);

        bytes memory signature = _signERC3009(
            buyerEOA,
            address(paymentEscrow),
            authorizedAmount,
            auth.validAfter,
            auth.validBefore,
            paymentDetailsHash,
            BUYER_EOA_PK
        );

        uint256 buyerBalanceBefore = mockERC3009Token.balanceOf(buyerEOA);

        vm.prank(operator);
        paymentEscrow.charge(chargeAmount, paymentDetails, signature);

        uint256 feeAmount = chargeAmount * FEE_BPS / 10_000;
        assertEq(mockERC3009Token.balanceOf(captureAddress), chargeAmount - feeAmount);
        assertEq(mockERC3009Token.balanceOf(feeRecipient), feeAmount);
        assertEq(mockERC3009Token.balanceOf(buyerEOA), buyerBalanceBefore - chargeAmount);
    }

    function test_charge_emitsCorrectEvents() public {
        uint256 authorizedAmount = 100e6;
        uint256 valueToCharge = 60e6; // Charge less than authorized to test refund events

        PaymentEscrow.Authorization memory auth = PaymentEscrow.Authorization({
            token: address(mockERC3009Token),
            buyer: buyerEOA,
            validAfter: block.timestamp - 1,
            validBefore: block.timestamp + 1 days,
            value: authorizedAmount,
            operator: operator,
            captureAddress: captureAddress,
            feeBps: FEE_BPS,
            feeRecipient: feeRecipient,
            salt: 0
        });

        bytes memory paymentDetails = abi.encode(auth);
        bytes32 paymentDetailsHash = keccak256(paymentDetails);

        bytes memory signature = _signERC3009(
            buyerEOA,
            address(paymentEscrow),
            authorizedAmount,
            auth.validAfter,
            auth.validBefore,
            paymentDetailsHash,
            BUYER_EOA_PK
        );

        // Record expected event
        vm.expectEmit(true, false, false, true);
        emit PaymentEscrow.PaymentCharged(paymentDetailsHash, valueToCharge);

        // Execute charge
        vm.prank(operator);
        paymentEscrow.charge(valueToCharge, paymentDetails, signature);
    }

    function test_charge_allowsRefund(uint256 authorizedAmount) public {
        uint256 buyerBalance = mockERC3009Token.balanceOf(buyerEOA);

        vm.assume(authorizedAmount > 3 && authorizedAmount <= buyerBalance);

        uint256 chargeAmount = authorizedAmount / 2;
        uint256 refundAmount = chargeAmount / 2;

        PaymentEscrow.Authorization memory auth = PaymentEscrow.Authorization({
            token: address(mockERC3009Token),
            buyer: buyerEOA,
            validAfter: block.timestamp - 1,
            validBefore: block.timestamp + 1 days,
            value: authorizedAmount,
            operator: operator,
            captureAddress: captureAddress,
            feeBps: FEE_BPS,
            feeRecipient: feeRecipient,
            salt: 0
        });

        bytes memory paymentDetails = abi.encode(auth);
        bytes32 paymentDetailsHash = keccak256(paymentDetails);

        bytes memory signature = _signERC3009(
            buyerEOA,
            address(paymentEscrow),
            authorizedAmount,
            auth.validAfter,
            auth.validBefore,
            paymentDetailsHash,
            BUYER_EOA_PK
        );

        // First charge the payment
        vm.prank(operator);
        paymentEscrow.charge(chargeAmount, paymentDetails, signature);

        // Fund operator for refund
        mockERC3009Token.mint(operator, refundAmount);
        vm.prank(operator);
        mockERC3009Token.approve(address(paymentEscrow), refundAmount);

        uint256 buyerBalanceBefore = mockERC3009Token.balanceOf(buyerEOA);
        uint256 operatorBalanceBefore = mockERC3009Token.balanceOf(operator);

        // Execute refund
        vm.prank(operator);
        paymentEscrow.refund(refundAmount, paymentDetails);

        // Verify balances
        assertEq(mockERC3009Token.balanceOf(operator), operatorBalanceBefore - refundAmount);
        assertEq(mockERC3009Token.balanceOf(buyerEOA), buyerBalanceBefore + refundAmount);

        // Try to refund more than remaining captured amount
        uint256 remainingCaptured = chargeAmount - refundAmount;
        vm.expectRevert(
            abi.encodeWithSelector(PaymentEscrow.RefundExceedsCapture.selector, chargeAmount, remainingCaptured)
        );
        vm.prank(operator);
        paymentEscrow.refund(chargeAmount, paymentDetails);
    }

    function test_charge_reverts_whenValueExceedsAuthorized(uint256 authorizedAmount) public {
        uint256 buyerBalance = mockERC3009Token.balanceOf(buyerEOA);

        vm.assume(authorizedAmount > 0 && authorizedAmount <= buyerBalance);
        uint256 chargeAmount = authorizedAmount + 1; // Always exceeds authorized

        PaymentEscrow.Authorization memory auth = PaymentEscrow.Authorization({
            token: address(mockERC3009Token),
            buyer: buyerEOA,
            validAfter: block.timestamp - 1,
            validBefore: block.timestamp + 1 days,
            value: authorizedAmount,
            operator: operator,
            captureAddress: captureAddress,
            feeBps: FEE_BPS,
            feeRecipient: feeRecipient,
            salt: 0
        });

        bytes memory paymentDetails = abi.encode(auth);

        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(PaymentEscrow.ValueLimitExceeded.selector, chargeAmount));
        paymentEscrow.charge(chargeAmount, paymentDetails, "");
    }

    function test_charge_reverts_whenAuthorizationIsVoided(uint256 authorizedAmount) public {
        uint256 buyerBalance = mockERC3009Token.balanceOf(buyerEOA);

        // Assume reasonable values and ensure we don't exceed buyer's balance
        vm.assume(authorizedAmount > 0 && authorizedAmount <= buyerBalance);

        PaymentEscrow.Authorization memory auth = PaymentEscrow.Authorization({
            token: address(mockERC3009Token),
            buyer: buyerEOA,
            validAfter: block.timestamp - 1,
            validBefore: block.timestamp + 1 days,
            value: authorizedAmount,
            operator: operator,
            captureAddress: captureAddress,
            feeBps: FEE_BPS,
            feeRecipient: feeRecipient,
            salt: 0
        });

        bytes memory paymentDetails = abi.encode(auth);
        bytes32 paymentDetailsHash = keccak256(paymentDetails);

        bytes memory signature = _signERC3009(
            buyerEOA,
            address(paymentEscrow),
            authorizedAmount,
            auth.validAfter,
            auth.validBefore,
            paymentDetailsHash,
            BUYER_EOA_PK
        );

        // First void the authorization
        vm.prank(operator);
        paymentEscrow.void(paymentDetails);

        // Then try to charge using the voided authorization
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(PaymentEscrow.VoidAuthorization.selector, paymentDetailsHash));
        paymentEscrow.charge(authorizedAmount, paymentDetails, signature);
    }
}
