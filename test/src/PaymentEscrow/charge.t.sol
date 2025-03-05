// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {PaymentEscrow} from "../../../src/PaymentEscrow.sol";
import {PaymentEscrowBase} from "../../base/PaymentEscrowBase.sol";

contract ChargeTest is PaymentEscrowBase {
    function test_charge_succeeds_whenValueEqualsAuthorized() public {
        uint256 authorizedAmount = 100e6;
        uint256 valueToCharge = authorizedAmount;

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
        paymentEscrow.charge(valueToCharge, paymentDetails, signature);

        uint256 feeAmount = valueToCharge * FEE_BPS / 10_000;
        assertEq(mockERC3009Token.balanceOf(captureAddress), valueToCharge - feeAmount);
        assertEq(mockERC3009Token.balanceOf(feeRecipient), feeAmount);
        assertEq(mockERC3009Token.balanceOf(buyerEOA), buyerBalanceBefore - valueToCharge);
    }

    function test_charge_succeeds_whenValueLessThanAuthorized() public {
        uint256 authorizedAmount = 100e6;
        uint256 valueToCharge = 60e6; // Charge less than authorized
        uint256 refundAmount = authorizedAmount - valueToCharge;

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
        paymentEscrow.charge(valueToCharge, paymentDetails, signature);

        uint256 feeAmount = valueToCharge * FEE_BPS / 10_000;
        assertEq(mockERC3009Token.balanceOf(captureAddress), valueToCharge - feeAmount);
        assertEq(mockERC3009Token.balanceOf(feeRecipient), feeAmount);
        assertEq(mockERC3009Token.balanceOf(buyerEOA), buyerBalanceBefore - valueToCharge);
        assertEq(mockERC3009Token.balanceOf(buyerEOA), buyerBalanceBefore - authorizedAmount + refundAmount);
    }

    function test_charge_reverts_whenValueExceedsAuthorized() public {
        uint256 authorizedAmount = 100e6;
        uint256 valueToCharge = 120e6; // Try to charge more than authorized

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
        vm.expectRevert(abi.encodeWithSelector(PaymentEscrow.ValueLimitExceeded.selector, valueToCharge));
        paymentEscrow.charge(valueToCharge, paymentDetails, signature);
    }
}
