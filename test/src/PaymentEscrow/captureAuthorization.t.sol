// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {PaymentEscrow} from "../../../src/PaymentEscrow.sol";
import {PaymentEscrowBase} from "../../base/PaymentEscrowBase.sol";

contract CaptureAuthorizationTest is PaymentEscrowBase {
    function test_captureAuthorization_succeeds_withFullAmount(uint256 authorizedAmount) public {
        uint256 buyerBalance = mockERC3009Token.balanceOf(buyerEOA);

        vm.assume(authorizedAmount > 0 && authorizedAmount <= buyerBalance);

        PaymentEscrow.Authorization memory auth = PaymentEscrow.Authorization({
            token: address(mockERC3009Token),
            from: buyerEOA,
            to: address(paymentEscrow),
            validAfter: block.timestamp - 1,
            validBefore: block.timestamp + 1 days,
            value: authorizedAmount,
            extraData: PaymentEscrow.ExtraData({
                salt: 0,
                operator: operator,
                captureAddress: captureAddress,
                feeBps: FEE_BPS,
                feeRecipient: feeRecipient
            })
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

        // First confirm the authorization
        vm.prank(operator);
        paymentEscrow.confirmAuthorization(authorizedAmount, paymentDetails, signature);

        uint256 feeAmount = authorizedAmount * FEE_BPS / 10_000;
        uint256 captureAddressExpectedBalance = authorizedAmount - feeAmount;

        // Then capture the full amount
        vm.prank(operator);
        paymentEscrow.captureAuthorization(authorizedAmount, paymentDetails);

        // Verify balances
        assertEq(mockERC3009Token.balanceOf(captureAddress), captureAddressExpectedBalance);
        assertEq(mockERC3009Token.balanceOf(feeRecipient), feeAmount);
        assertEq(mockERC3009Token.balanceOf(address(paymentEscrow)), 0);
    }

    function test_captureAuthorization_succeeds_withPartialAmount(uint256 authorizedAmount) public {
        uint256 buyerBalance = mockERC3009Token.balanceOf(buyerEOA);

        vm.assume(authorizedAmount > 1 && authorizedAmount <= buyerBalance);
        uint256 captureAmount = authorizedAmount / 2;

        PaymentEscrow.Authorization memory auth = PaymentEscrow.Authorization({
            token: address(mockERC3009Token),
            from: buyerEOA,
            to: address(paymentEscrow),
            validAfter: block.timestamp - 1,
            validBefore: block.timestamp + 1 days,
            value: authorizedAmount,
            extraData: PaymentEscrow.ExtraData({
                salt: 0,
                operator: operator,
                captureAddress: captureAddress,
                feeBps: FEE_BPS,
                feeRecipient: feeRecipient
            })
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

        // First confirm the authorization
        vm.prank(operator);
        paymentEscrow.confirmAuthorization(authorizedAmount, paymentDetails, signature);

        uint256 feeAmount = captureAmount * FEE_BPS / 10_000;
        uint256 captureAddressExpectedBalance = captureAmount - feeAmount;

        // Then capture partial amount
        vm.prank(operator);
        paymentEscrow.captureAuthorization(captureAmount, paymentDetails);

        // Verify balances and state
        assertEq(mockERC3009Token.balanceOf(captureAddress), captureAddressExpectedBalance);
        assertEq(mockERC3009Token.balanceOf(feeRecipient), feeAmount);
        assertEq(mockERC3009Token.balanceOf(address(paymentEscrow)), authorizedAmount - captureAmount);
    }

    function test_captureAuthorization_succeeds_withMultipleCaptures(uint256 authorizedAmount) public {
        uint256 buyerBalance = mockERC3009Token.balanceOf(buyerEOA);

        vm.assume(authorizedAmount > 2 && authorizedAmount <= buyerBalance);
        uint256 firstCaptureAmount = authorizedAmount / 2;
        uint256 secondCaptureAmount = authorizedAmount - firstCaptureAmount;

        PaymentEscrow.Authorization memory auth = PaymentEscrow.Authorization({
            token: address(mockERC3009Token),
            from: buyerEOA,
            to: address(paymentEscrow),
            validAfter: block.timestamp - 1,
            validBefore: block.timestamp + 1 days,
            value: authorizedAmount,
            extraData: PaymentEscrow.ExtraData({
                salt: 0,
                operator: operator,
                captureAddress: captureAddress,
                feeBps: FEE_BPS,
                feeRecipient: feeRecipient
            })
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

        // First confirm the authorization
        vm.prank(operator);
        paymentEscrow.confirmAuthorization(authorizedAmount, paymentDetails, signature);

        // First capture
        vm.prank(operator);
        paymentEscrow.captureAuthorization(firstCaptureAmount, paymentDetails);

        // Second capture
        vm.prank(operator);
        paymentEscrow.captureAuthorization(secondCaptureAmount, paymentDetails);

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

    function test_captureAuthorization_reverts_whenInsufficientAuthorization(uint256 authorizedAmount) public {
        uint256 buyerBalance = mockERC3009Token.balanceOf(buyerEOA);

        vm.assume(authorizedAmount > 0 && authorizedAmount <= buyerBalance);
        uint256 captureAmount = authorizedAmount + 1; // Try to capture more than authorized

        PaymentEscrow.Authorization memory auth = PaymentEscrow.Authorization({
            token: address(mockERC3009Token),
            from: buyerEOA,
            to: address(paymentEscrow),
            validAfter: block.timestamp - 1,
            validBefore: block.timestamp + 1 days,
            value: authorizedAmount,
            extraData: PaymentEscrow.ExtraData({
                salt: 0,
                operator: operator,
                captureAddress: captureAddress,
                feeBps: FEE_BPS,
                feeRecipient: feeRecipient
            })
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

        // First confirm the authorization
        vm.prank(operator);
        paymentEscrow.confirmAuthorization(authorizedAmount, paymentDetails, signature);

        // Try to capture more than authorized
        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                PaymentEscrow.InsufficientAuthorization.selector, paymentDetailsHash, authorizedAmount, captureAmount
            )
        );
        paymentEscrow.captureAuthorization(captureAmount, paymentDetails);
    }

    function test_captureAuthorization_reverts_whenNotOperator() public {
        uint256 authorizedAmount = 100e6;

        PaymentEscrow.Authorization memory auth = PaymentEscrow.Authorization({
            token: address(mockERC3009Token),
            from: buyerEOA,
            to: address(paymentEscrow),
            validAfter: block.timestamp - 1,
            validBefore: block.timestamp + 1 days,
            value: authorizedAmount,
            extraData: PaymentEscrow.ExtraData({
                salt: 0,
                operator: operator,
                captureAddress: captureAddress,
                feeBps: FEE_BPS,
                feeRecipient: feeRecipient
            })
        });

        bytes memory paymentDetails = abi.encode(auth);

        address randomAddress = makeAddr("randomAddress");
        vm.prank(randomAddress);
        vm.expectRevert(abi.encodeWithSelector(PaymentEscrow.InvalidSender.selector, randomAddress, operator));
        paymentEscrow.captureAuthorization(authorizedAmount, paymentDetails);
    }

    function test_captureAuthorization_emitsCorrectEvents() public {
        uint256 authorizedAmount = 100e6;
        uint256 captureAmount = 60e6;

        PaymentEscrow.Authorization memory auth = PaymentEscrow.Authorization({
            token: address(mockERC3009Token),
            from: buyerEOA,
            to: address(paymentEscrow),
            validAfter: block.timestamp - 1,
            validBefore: block.timestamp + 1 days,
            value: authorizedAmount,
            extraData: PaymentEscrow.ExtraData({
                salt: 0,
                operator: operator,
                captureAddress: captureAddress,
                feeBps: FEE_BPS,
                feeRecipient: feeRecipient
            })
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

        // First confirm the authorization
        vm.prank(operator);
        paymentEscrow.confirmAuthorization(authorizedAmount, paymentDetails, signature);

        // Record expected event
        vm.expectEmit(true, false, false, true);
        emit PaymentEscrow.PaymentCaptured(paymentDetailsHash, captureAmount);

        // Execute capture
        vm.prank(operator);
        paymentEscrow.captureAuthorization(captureAmount, paymentDetails);
    }

    function test_captureAuthorization_withZeroFees() public {
        uint256 amount = 100e6;

        PaymentEscrow.Authorization memory auth = PaymentEscrow.Authorization({
            token: address(mockERC3009Token),
            from: buyerEOA,
            to: address(paymentEscrow),
            validAfter: block.timestamp - 1,
            validBefore: block.timestamp + 1 days,
            value: amount,
            extraData: PaymentEscrow.ExtraData({
                salt: 0,
                operator: operator,
                captureAddress: captureAddress,
                feeBps: 0,
                feeRecipient: address(0)
            })
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

        vm.startPrank(operator);
        paymentEscrow.confirmAuthorization(amount, paymentDetails, signature);
        paymentEscrow.captureAuthorization(amount, paymentDetails);
        vm.stopPrank();

        // With zero fees, entire amount should go to captureAddress
        assertEq(mockERC3009Token.balanceOf(captureAddress), amount);
        assertEq(mockERC3009Token.balanceOf(feeRecipient), 0);
    }
}
