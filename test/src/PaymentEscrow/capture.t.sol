// // SPDX-License-Identifier: UNLICENSED
// pragma solidity ^0.8.13;

// import {SpendPermissionManager} from "spend-permissions/SpendPermissionManager.sol";

// import {PaymentEscrowBase} from "../../base/PaymentEscrowBase.sol";

// contract CaptureTest is PaymentEscrowBase {
//     function setUp() public {
//         _setUpPaymentEscrow();
//     }

//     function test_capture_success_erc20(uint160 value, uint16 feeBps) public {
//         vm.assume(value > 0);
//         vm.assume(feeBps <= 10_000);
//         address operator = _createReceiver();
//         address merchant = _createReceiver();
//         address feeRecipient = _createReceiver();

//         SpendPermissionManager.SpendPermission memory permission =
//             _createPaymentSpendPermission(address(mockERC20), value, operator, merchant, feeBps, feeRecipient);
//         bytes memory signature = _signPaymentSpendPermission(permission);

//         mockERC20.mint(address(account), value);

//         vm.prank(operator);
//         paymentEscrow.authorize(value, abi.encode(permission), signature);

//         assertEq(mockERC20.balanceOf(address(account)), 0);
//         assertEq(mockERC20.balanceOf(address(paymentEscrow)), value);

//         vm.prank(operator);
//         paymentEscrow.capture(value, abi.encode(permission));

//         uint256 feeAmount = uint256(value) * feeBps / 10_000;

//         assertEq(mockERC20.balanceOf(address(account)), 0);
//         assertEq(mockERC20.balanceOf(address(paymentEscrow)), 0);
//         assertEq(mockERC20.balanceOf(feeRecipient), feeAmount);
//         assertEq(mockERC20.balanceOf(merchant), value - feeAmount);
//     }

//     function test_capture_success_native(uint160 value, uint16 feeBps) public {
//         vm.assume(value > 0);
//         vm.assume(feeBps <= 10_000);
//         address operator = _createReceiver();
//         address merchant = _createReceiver();
//         address feeRecipient = _createReceiver();

//         SpendPermissionManager.SpendPermission memory permission =
//             _createPaymentSpendPermission(NATIVE_TOKEN, value, operator, merchant, feeBps, feeRecipient);
//         bytes memory signature = _signPaymentSpendPermission(permission);

//         vm.deal(address(account), value);

//         vm.prank(operator);
//         paymentEscrow.authorize(value, abi.encode(permission), signature);

//         assertEq(address(account).balance, 0);
//         assertEq(address(paymentEscrow).balance, value);

//         vm.prank(operator);
//         paymentEscrow.capture(value, abi.encode(permission));

//         uint256 feeAmount = uint256(value) * feeBps / 10_000;

//         assertEq(address(account).balance, 0);
//         assertEq(address(paymentEscrow).balance, 0);
//         assertEq(feeRecipient.balance, feeAmount);
//         assertEq(merchant.balance, value - feeAmount);
//     }
// }
