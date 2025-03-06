// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.13;

import {PaymentEscrow} from "../../../src/PaymentEscrow.sol";
import {PaymentEscrowBase} from "../../base/PaymentEscrowBase.sol";

contract VoidAuthorizationTest is PaymentEscrowBase {
    function test_void_succeeds_withNoEscrowedFunds(uint256 authorizedAmount) public {
        uint256 buyerBalance = mockERC3009Token.balanceOf(buyerEOA);

        vm.assume(authorizedAmount > 0 && authorizedAmount <= buyerBalance);

        PaymentEscrow.Authorization memory auth = _createPaymentEscrowAuthorization(buyerEOA, authorizedAmount);

        bytes memory paymentDetails = abi.encode(auth);
        bytes32 paymentDetailsHash = keccak256(paymentDetails);

        vm.prank(operator);
        vm.expectEmit(true, false, false, false);
        emit PaymentEscrow.PaymentVoided(paymentDetailsHash);
        paymentEscrow.void(paymentDetails);

        bytes memory signature = _signERC3009(
            buyerEOA,
            address(paymentEscrow),
            authorizedAmount,
            auth.validAfter,
            auth.validBefore,
            paymentDetailsHash,
            BUYER_EOA_PK
        );

        // try to confirm authorization and see revert
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(PaymentEscrow.VoidAuthorization.selector, paymentDetailsHash));
        paymentEscrow.authorize(authorizedAmount, paymentDetails, signature);
    }

    function test_void_succeeds_withEscrowedFunds(uint256 authorizedAmount) public {
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

        // First confirm the authorization to escrow funds
        vm.prank(operator);
        paymentEscrow.authorize(authorizedAmount, paymentDetails, signature);

        uint256 buyerBalanceBefore = mockERC3009Token.balanceOf(buyerEOA);
        uint256 escrowBalanceBefore = mockERC3009Token.balanceOf(address(paymentEscrow));

        // Then void the authorization
        vm.prank(operator);
        vm.expectEmit(true, false, false, false);
        emit PaymentEscrow.PaymentVoided(paymentDetailsHash);
        paymentEscrow.void(paymentDetails);

        // Verify funds were returned to buyer
        assertEq(mockERC3009Token.balanceOf(buyerEOA), buyerBalanceBefore + escrowBalanceBefore);
        assertEq(mockERC3009Token.balanceOf(address(paymentEscrow)), 0);
    }

    function test_void_succeeds_whenAlreadyVoided(uint256 authorizedAmount) public {
        uint256 buyerBalance = mockERC3009Token.balanceOf(buyerEOA);

        vm.assume(authorizedAmount > 0 && authorizedAmount <= buyerBalance);

        PaymentEscrow.Authorization memory auth = _createPaymentEscrowAuthorization(buyerEOA, authorizedAmount);

        bytes memory paymentDetails = abi.encode(auth);
        bytes32 paymentDetailsHash = keccak256(paymentDetails);

        // Void the authorization first time
        vm.prank(operator);
        vm.expectEmit(true, false, false, false);
        emit PaymentEscrow.PaymentVoided(paymentDetailsHash);
        paymentEscrow.void(paymentDetails);

        // Void the authorization second time
        vm.prank(operator);
        paymentEscrow.void(paymentDetails);
    }

    function test_void_reverts_whenNotOperatorOrCaptureAddress() public {
        uint256 authorizedAmount = 100e6;

        PaymentEscrow.Authorization memory auth = _createPaymentEscrowAuthorization(buyerEOA, authorizedAmount);

        bytes memory paymentDetails = abi.encode(auth);

        address randomAddress = makeAddr("randomAddress");
        vm.prank(randomAddress);
        vm.expectRevert(abi.encodeWithSelector(PaymentEscrow.InvalidSender.selector, randomAddress));
        paymentEscrow.void(paymentDetails);
    }

    function test_void_reverts_whenCalledByBuyerBeforeCaptureDeadline(uint48 captureDeadline) public {
        vm.assume(captureDeadline > 0);
        uint256 authorizedAmount = 100e6;

        PaymentEscrow.Authorization memory auth = _createPaymentEscrowAuthorization(buyerEOA, authorizedAmount);
        auth.captureDeadline = captureDeadline;
        vm.warp(captureDeadline - 1);

        bytes memory paymentDetails = abi.encode(auth);

        vm.prank(buyerEOA);
        vm.expectRevert(
            abi.encodeWithSelector(PaymentEscrow.BeforeCaptureDeadline.selector, block.timestamp, captureDeadline)
        );
        paymentEscrow.void(paymentDetails);
    }

    function test_void_succeeds_whenCalledByCaptureAddress(uint256 authorizedAmount) public {
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

        // First confirm the authorization to escrow funds
        vm.prank(operator);
        paymentEscrow.authorize(authorizedAmount, paymentDetails, signature);

        uint256 buyerBalanceBefore = mockERC3009Token.balanceOf(buyerEOA);
        uint256 escrowBalanceBefore = mockERC3009Token.balanceOf(address(paymentEscrow));

        // Then void the authorization as captureAddress
        vm.prank(captureAddress);
        vm.expectEmit(true, false, false, false);
        emit PaymentEscrow.PaymentVoided(paymentDetailsHash);
        paymentEscrow.void(paymentDetails);

        // Verify funds were returned to buyer
        assertEq(mockERC3009Token.balanceOf(buyerEOA), buyerBalanceBefore + escrowBalanceBefore);
        assertEq(mockERC3009Token.balanceOf(address(paymentEscrow)), 0);
    }

    function test_void_succeeds_whenCalledByBuyer(uint256 authorizedAmount, uint48 captureDeadline) public {
        uint256 buyerBalance = mockERC3009Token.balanceOf(buyerEOA);

        vm.assume(authorizedAmount > 0 && authorizedAmount <= buyerBalance);

        PaymentEscrow.Authorization memory auth = _createPaymentEscrowAuthorization(buyerEOA, authorizedAmount);
        vm.assume(captureDeadline > auth.validAfter && captureDeadline < auth.validBefore);

        auth.captureDeadline = captureDeadline;
        vm.warp(captureDeadline);

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

        // First confirm the authorization to escrow funds
        vm.prank(operator);
        paymentEscrow.authorize(authorizedAmount, paymentDetails, signature);

        uint256 buyerBalanceBefore = mockERC3009Token.balanceOf(buyerEOA);
        uint256 escrowBalanceBefore = mockERC3009Token.balanceOf(address(paymentEscrow));

        // Then void the authorization as captureAddress
        vm.prank(buyerEOA);
        vm.expectEmit(true, false, false, false);
        emit PaymentEscrow.PaymentVoided(paymentDetailsHash);
        paymentEscrow.void(paymentDetails);

        // Verify funds were returned to buyer
        assertEq(mockERC3009Token.balanceOf(buyerEOA), buyerBalanceBefore + escrowBalanceBefore);
        assertEq(mockERC3009Token.balanceOf(address(paymentEscrow)), 0);
    }

    function test_void_emitsCorrectEvents() public {
        uint256 authorizedAmount = 100e6;

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

        // First confirm the authorization to escrow funds
        vm.prank(operator);
        paymentEscrow.authorize(authorizedAmount, paymentDetails, signature);

        // Record all expected events in order
        vm.expectEmit(true, false, false, false);
        emit PaymentEscrow.PaymentVoided(paymentDetailsHash);

        // Then void the authorization and verify events
        vm.prank(operator);
        paymentEscrow.void(paymentDetails);
    }
}
