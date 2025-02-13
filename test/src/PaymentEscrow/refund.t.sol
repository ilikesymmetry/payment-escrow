// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {SpendPermissionManager} from "spend-permissions/SpendPermissionManager.sol";

import {PaymentEscrowBase} from "../../base/PaymentEscrowBase.sol";

contract RefundTest is PaymentEscrowBase {
    function setUp() public {
        _setUpPaymentEscrow();
    }

    function test_refund_success_erc20(uint160 value, uint16 feeBps) public {
        vm.assume(value > 0);
        vm.assume(feeBps <= 10_000);
        address operator = _createReceiver();
        address merchant = _createReceiver();
        address feeRecipient = _createReceiver();

        SpendPermissionManager.SpendPermission memory permission =
            _createPaymentSpendPermission(address(mockERC20), value, operator, merchant, feeBps, feeRecipient);
        bytes memory signature = _signPaymentSpendPermission(permission);

        mockERC20.mint(address(account), value);

        vm.prank(operator);
        paymentEscrow.authorize(value, abi.encode(permission), signature);

        assertEq(mockERC20.balanceOf(address(account)), 0);
        assertEq(mockERC20.balanceOf(address(paymentEscrow)), value);

        vm.prank(operator);
        paymentEscrow.capture(value, abi.encode(permission));

        uint256 feeAmount = uint256(value) * feeBps / 10_000;

        assertEq(mockERC20.balanceOf(address(account)), 0);
        assertEq(mockERC20.balanceOf(address(paymentEscrow)), 0);
        assertEq(mockERC20.balanceOf(feeRecipient), feeAmount);
        assertEq(mockERC20.balanceOf(merchant), value - feeAmount);

        mockERC20.mint(operator, value);
        vm.startPrank(operator);
        mockERC20.approve(address(paymentEscrow), value);
        paymentEscrow.refund(value, abi.encode(permission));

        assertEq(mockERC20.balanceOf(address(operator)), 0);
        assertEq(mockERC20.balanceOf(address(account)), value);
        assertEq(mockERC20.balanceOf(address(paymentEscrow)), 0);
        assertEq(mockERC20.balanceOf(feeRecipient), feeAmount);
        assertEq(mockERC20.balanceOf(merchant), value - feeAmount);
    }

    function test_refund_success_native(uint160 value, uint16 feeBps) public {
        vm.assume(value > 0);
        vm.assume(feeBps <= 10_000);
        address operator = _createReceiver();
        address merchant = _createReceiver();
        address feeRecipient = _createReceiver();

        SpendPermissionManager.SpendPermission memory permission =
            _createPaymentSpendPermission(NATIVE_TOKEN, value, operator, merchant, feeBps, feeRecipient);
        bytes memory signature = _signPaymentSpendPermission(permission);

        vm.deal(address(account), value);

        vm.prank(operator);
        paymentEscrow.authorize(value, abi.encode(permission), signature);

        assertEq(address(account).balance, 0);
        assertEq(address(paymentEscrow).balance, value);

        vm.prank(operator);
        paymentEscrow.capture(value, abi.encode(permission));

        uint256 feeAmount = uint256(value) * feeBps / 10_000;

        assertEq(address(account).balance, 0);
        assertEq(address(paymentEscrow).balance, 0);
        assertEq(feeRecipient.balance, feeAmount);
        assertEq(merchant.balance, value - feeAmount);

        vm.deal(operator, value);
        vm.startPrank(operator);
        paymentEscrow.refund{value: value}(value, abi.encode(permission));

        assertEq(operator.balance, 0);
        assertEq(address(account).balance, value);
        assertEq(address(paymentEscrow).balance, 0);
        assertEq(feeRecipient.balance, feeAmount);
        assertEq(merchant.balance, value - feeAmount);
    }
}
