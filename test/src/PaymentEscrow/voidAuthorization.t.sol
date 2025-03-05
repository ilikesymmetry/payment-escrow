// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {PaymentEscrow} from "../../../src/PaymentEscrow.sol";
import {PaymentEscrowBase} from "../../base/PaymentEscrowBase.sol";

contract VoidAuthorizationTest is PaymentEscrowBase {
    function test_voidAuthorization_succeeds_withNoEscrowedFunds() public {
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
        bytes32 paymentDetailsHash = keccak256(paymentDetails);

        vm.prank(operator);
        vm.expectEmit(true, false, false, false);
        emit PaymentEscrow.AuthorizationVoided(paymentDetailsHash);
        paymentEscrow.voidAuthorization(paymentDetails);

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
        paymentEscrow.confirmAuthorization(authorizedAmount, paymentDetails, signature);
    }

    function test_voidAuthorization_succeeds_withEscrowedFunds() public {
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
        paymentEscrow.confirmAuthorization(authorizedAmount, paymentDetails, signature);

        uint256 buyerBalanceBefore = mockERC3009Token.balanceOf(buyerEOA);
        uint256 escrowBalanceBefore = mockERC3009Token.balanceOf(address(paymentEscrow));

        // Then void the authorization
        vm.prank(operator);
        vm.expectEmit(true, false, false, false);
        emit PaymentEscrow.AuthorizationVoided(paymentDetailsHash);
        vm.expectEmit(true, false, false, true);
        emit PaymentEscrow.AuthorizationDecreased(paymentDetailsHash, authorizedAmount);
        vm.expectEmit(true, false, false, false);
        emit PaymentEscrow.PaymentVoided(paymentDetailsHash);
        paymentEscrow.voidAuthorization(paymentDetails);

        // Verify funds were returned to buyer
        assertEq(mockERC3009Token.balanceOf(buyerEOA), buyerBalanceBefore + escrowBalanceBefore);
        assertEq(mockERC3009Token.balanceOf(address(paymentEscrow)), 0);
    }

    function test_voidAuthorization_succeeds_whenAlreadyVoided() public {
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
        bytes32 paymentDetailsHash = keccak256(paymentDetails);

        // Void the authorization first time
        vm.prank(operator);
        paymentEscrow.voidAuthorization(paymentDetails);

        // Void the authorization second time
        vm.prank(operator);
        vm.expectEmit(true, false, false, false);
        emit PaymentEscrow.AuthorizationVoided(paymentDetailsHash);
        paymentEscrow.voidAuthorization(paymentDetails);
    }

    function test_voidAuthorization_reverts_whenNotOperatorOrCaptureAddress() public {
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
        vm.expectRevert(
            abi.encodeWithSelector(PaymentEscrow.InvalidRefundSender.selector, randomAddress, operator, captureAddress)
        );
        paymentEscrow.voidAuthorization(paymentDetails);
    }

    function test_voidAuthorization_succeeds_whenCalledByCaptureAddress() public {
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
        paymentEscrow.confirmAuthorization(authorizedAmount, paymentDetails, signature);

        uint256 buyerBalanceBefore = mockERC3009Token.balanceOf(buyerEOA);
        uint256 escrowBalanceBefore = mockERC3009Token.balanceOf(address(paymentEscrow));

        // Then void the authorization as captureAddress
        vm.prank(captureAddress);
        vm.expectEmit(true, false, false, false);
        emit PaymentEscrow.AuthorizationVoided(paymentDetailsHash);
        vm.expectEmit(true, false, false, true);
        emit PaymentEscrow.AuthorizationDecreased(paymentDetailsHash, authorizedAmount);
        vm.expectEmit(true, false, false, false);
        emit PaymentEscrow.PaymentVoided(paymentDetailsHash);
        paymentEscrow.voidAuthorization(paymentDetails);

        // Verify funds were returned to buyer
        assertEq(mockERC3009Token.balanceOf(buyerEOA), buyerBalanceBefore + escrowBalanceBefore);
        assertEq(mockERC3009Token.balanceOf(address(paymentEscrow)), 0);
    }

    function test_voidAuthorization_emitsCorrectEvents() public {
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
        paymentEscrow.confirmAuthorization(authorizedAmount, paymentDetails, signature);

        // Record all expected events in order
        vm.expectEmit(true, false, false, false);
        emit PaymentEscrow.AuthorizationVoided(paymentDetailsHash);

        vm.expectEmit(true, false, false, true);
        emit PaymentEscrow.AuthorizationDecreased(paymentDetailsHash, authorizedAmount);

        vm.expectEmit(true, false, false, false);
        emit PaymentEscrow.PaymentVoided(paymentDetailsHash);

        // Then void the authorization and verify events
        vm.prank(operator);
        paymentEscrow.voidAuthorization(paymentDetails);
    }
}
