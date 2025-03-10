// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.13;

import {PaymentEscrow} from "../../../src/PaymentEscrow.sol";
import {PaymentEscrowBase} from "../../base/PaymentEscrowBase.sol";

contract CaptureAuthorizationTest is PaymentEscrowBase {
    function test_capture_succeeds_withFullAmount(uint256 authorizedAmount) public {
        uint256 buyerBalance = mockERC3009Token.balanceOf(buyerEOA);

        vm.assume(authorizedAmount > 0 && authorizedAmount <= buyerBalance);

        PaymentEscrow.Authorization memory auth = _createPaymentEscrowAuthorization(buyerEOA, authorizedAmount);

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

        // First confirm the authorization
        vm.prank(operator);
        paymentEscrow.authorize(authorizedAmount, paymentDetails, signature);

        uint256 feeAmount = authorizedAmount * FEE_BPS / 10_000;
        uint256 captureAddressExpectedBalance = authorizedAmount - feeAmount;

        // Then capture the full amount
        vm.prank(operator);
        paymentEscrow.capture(authorizedAmount, paymentDetails);

        // Verify balances
        assertEq(mockERC3009Token.balanceOf(captureAddress), captureAddressExpectedBalance);
        assertEq(mockERC3009Token.balanceOf(feeRecipient), feeAmount);
        assertEq(mockERC3009Token.balanceOf(address(paymentEscrow)), 0);
    }

    function test_capture_succeeds_withPartialAmount(uint256 authorizedAmount) public {
        uint256 buyerBalance = mockERC3009Token.balanceOf(buyerEOA);

        vm.assume(authorizedAmount > 1 && authorizedAmount <= buyerBalance);
        uint256 captureAmount = authorizedAmount / 2;

        PaymentEscrow.Authorization memory auth = _createPaymentEscrowAuthorization(buyerEOA, authorizedAmount);

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

        // First confirm the authorization
        vm.prank(operator);
        paymentEscrow.authorize(authorizedAmount, paymentDetails, signature);

        uint256 feeAmount = captureAmount * FEE_BPS / 10_000;
        uint256 captureAddressExpectedBalance = captureAmount - feeAmount;

        // Then capture partial amount
        vm.prank(operator);
        paymentEscrow.capture(captureAmount, paymentDetails);

        // Verify balances and state
        assertEq(mockERC3009Token.balanceOf(captureAddress), captureAddressExpectedBalance);
        assertEq(mockERC3009Token.balanceOf(feeRecipient), feeAmount);
        assertEq(mockERC3009Token.balanceOf(address(paymentEscrow)), authorizedAmount - captureAmount);
    }

    function test_capture_succeeds_withMultipleCaptures(uint256 authorizedAmount) public {
        uint256 buyerBalance = mockERC3009Token.balanceOf(buyerEOA);

        vm.assume(authorizedAmount > 2 && authorizedAmount <= buyerBalance);
        uint256 firstCaptureAmount = authorizedAmount / 2;
        uint256 secondCaptureAmount = authorizedAmount - firstCaptureAmount;

        PaymentEscrow.Authorization memory auth = _createPaymentEscrowAuthorization(buyerEOA, authorizedAmount);

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

        // First confirm the authorization
        vm.prank(operator);
        paymentEscrow.authorize(authorizedAmount, paymentDetails, signature);

        // First capture
        vm.prank(operator);
        paymentEscrow.capture(firstCaptureAmount, paymentDetails);

        // Second capture
        vm.prank(operator);
        paymentEscrow.capture(secondCaptureAmount, paymentDetails);

        // Calculate fees for each capture separately to match contract behavior
        uint256 firstFeesAmount = firstCaptureAmount * FEE_BPS / 10_000;
        uint256 secondFeesAmount = secondCaptureAmount * FEE_BPS / 10_000;
        uint256 totalFeeAmount = firstFeesAmount + secondFeesAmount;

        // Calculate expected capture address balance by subtracting fees from each capture
        uint256 captureAddressExpectedBalance =
            (firstCaptureAmount - firstFeesAmount) + (secondCaptureAmount - secondFeesAmount);

        // Verify final state
        assertEq(mockERC3009Token.balanceOf(captureAddress), captureAddressExpectedBalance);
        assertEq(mockERC3009Token.balanceOf(feeRecipient), totalFeeAmount);
        assertEq(mockERC3009Token.balanceOf(address(paymentEscrow)), 0);
    }

    function test_capture_reverts_whenAfterCaptureDeadline(
        uint256 authorizedAmount,
        uint256 captureAmount,
        uint48 captureDeadline
    ) public {
        vm.assume(captureDeadline > 0 && captureDeadline < type(uint40).max);
        uint256 buyerBalance = mockERC3009Token.balanceOf(buyerEOA);

        vm.assume(authorizedAmount > 0 && authorizedAmount <= buyerBalance);
        vm.assume(captureAmount > 0 && captureAmount <= authorizedAmount);

        PaymentEscrow.Authorization memory auth = _createPaymentEscrowAuthorization(buyerEOA, authorizedAmount);
        auth.captureDeadline = captureDeadline;
        vm.warp(captureDeadline + 1);

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

        // First confirm the authorization
        vm.prank(operator);
        paymentEscrow.authorize(authorizedAmount, paymentDetails, signature);

        // Try to capture more than authorized
        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(PaymentEscrow.AfterCaptureDeadline.selector, block.timestamp, captureDeadline)
        );
        paymentEscrow.capture(captureAmount, paymentDetails);
    }

    function test_capture_reverts_whenInsufficientAuthorization(uint256 authorizedAmount) public {
        uint256 buyerBalance = mockERC3009Token.balanceOf(buyerEOA);

        vm.assume(authorizedAmount > 0 && authorizedAmount <= buyerBalance);
        uint256 captureAmount = authorizedAmount + 1; // Try to capture more than authorized

        PaymentEscrow.Authorization memory auth = _createPaymentEscrowAuthorization(buyerEOA, authorizedAmount);

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

        // First confirm the authorization
        vm.prank(operator);
        paymentEscrow.authorize(authorizedAmount, paymentDetails, signature);

        // Try to capture more than authorized
        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                PaymentEscrow.InsufficientAuthorization.selector, paymentDetailsHash, authorizedAmount, captureAmount
            )
        );
        paymentEscrow.capture(captureAmount, paymentDetails);
    }

    function test_capture_reverts_whenNotOperator() public {
        uint256 authorizedAmount = 100e6;

        PaymentEscrow.Authorization memory auth = _createPaymentEscrowAuthorization(buyerEOA, authorizedAmount);

        bytes memory paymentDetails = abi.encode(auth);

        address randomAddress = makeAddr("randomAddress");
        vm.prank(randomAddress);
        vm.expectRevert(abi.encodeWithSelector(PaymentEscrow.InvalidSender.selector, randomAddress));
        paymentEscrow.capture(authorizedAmount, paymentDetails);
    }

    function test_capture_emitsCorrectEvents() public {
        uint256 authorizedAmount = 100e6;
        uint256 captureAmount = 60e6;

        PaymentEscrow.Authorization memory auth = _createPaymentEscrowAuthorization(buyerEOA, authorizedAmount);

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

        // First confirm the authorization
        vm.prank(operator);
        paymentEscrow.authorize(authorizedAmount, paymentDetails, signature);

        // Record expected event
        vm.expectEmit(true, false, false, true);
        emit PaymentEscrow.PaymentCaptured(paymentDetailsHash, captureAmount);

        // Execute capture
        vm.prank(operator);
        paymentEscrow.capture(captureAmount, paymentDetails);
    }
}
