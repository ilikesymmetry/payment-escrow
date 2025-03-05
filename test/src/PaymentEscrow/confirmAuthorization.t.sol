// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {PaymentEscrow} from "../../../src/PaymentEscrow.sol";
import {PaymentEscrowBase} from "../../base/PaymentEscrowBase.sol";

contract ConfirmAuthorizationTest is PaymentEscrowBase {
    function test_confirmAuthorization_succeeds_whenValueEqualsAuthorized() public {
        uint256 authorizedAmount = 100e6;
        uint256 valueToConfirm = authorizedAmount;

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

        uint256 buyerBalanceBefore = mockERC3009Token.balanceOf(buyerEOA);

        vm.prank(operator);
        paymentEscrow.confirmAuthorization(valueToConfirm, paymentDetails, signature);

        assertEq(mockERC3009Token.balanceOf(address(paymentEscrow)), valueToConfirm);
        assertEq(mockERC3009Token.balanceOf(buyerEOA), buyerBalanceBefore - valueToConfirm);
    }

    function test_confirmAuthorization_succeeds_whenValueLessThanAuthorized() public {
        uint256 authorizedAmount = 100e6;
        uint256 valueToConfirm = 60e6; // Confirm less than authorized
        uint256 refundAmount = authorizedAmount - valueToConfirm;

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

        uint256 buyerBalanceBefore = mockERC3009Token.balanceOf(buyerEOA);

        vm.prank(operator);
        paymentEscrow.confirmAuthorization(valueToConfirm, paymentDetails, signature);

        assertEq(mockERC3009Token.balanceOf(address(paymentEscrow)), valueToConfirm);
        assertEq(mockERC3009Token.balanceOf(buyerEOA), buyerBalanceBefore - authorizedAmount + refundAmount);
    }

    function test_confirmAuthorization_reverts_whenValueExceedsAuthorized() public {
        uint256 authorizedAmount = 100e6;
        uint256 valueToConfirm = 120e6; // Try to confirm more than authorized

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

        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(PaymentEscrow.ValueLimitExceeded.selector, valueToConfirm));
        paymentEscrow.confirmAuthorization(valueToConfirm, paymentDetails, signature);
    }

    function test_confirmAuthorization_reverts_whenAuthorizationIsVoided() public {
        uint256 authorizedAmount = 100e6;
        uint256 valueToConfirm = authorizedAmount;

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

        // First void the authorization
        vm.prank(operator);
        paymentEscrow.voidAuthorization(paymentDetails);

        // Then try to confirm the voided authorization
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(PaymentEscrow.VoidAuthorization.selector, paymentDetailsHash));
        paymentEscrow.confirmAuthorization(valueToConfirm, paymentDetails, signature);
    }

    function test_confirmAuthorization_emitsCorrectEvents() public {
        uint256 authorizedAmount = 100e6;
        uint256 valueToConfirm = 60e6; // Confirm less than authorized to test refund events

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

        // Record expected event
        vm.expectEmit(true, false, false, true);
        emit PaymentEscrow.AuthorizationIncreased(paymentDetailsHash, valueToConfirm);

        // Execute confirmation
        vm.prank(operator);
        paymentEscrow.confirmAuthorization(valueToConfirm, paymentDetails, signature);
    }
}
