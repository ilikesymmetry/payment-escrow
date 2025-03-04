// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {console2} from "forge-std/console2.sol";

import {IERC1271} from "openzeppelin-contracts/contracts/interfaces/IERC1271.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {CoinbaseSmartWallet} from "smart-wallet/CoinbaseSmartWallet.sol";
import {MagicSpend} from "magic-spend/MagicSpend.sol";
import {PaymentEscrow} from "./PaymentEscrow.sol";

/// @title MagicSpendHook
/// @notice A hook contract for drawing funds into a smart wallet via magic spend.
contract MagicSpendHook {
    /// @notice The PaymentEscrow contract instance
    PaymentEscrow immutable paymentEscrow;

    /// @notice The MagicSpend contract instance
    address immutable magicSpend;

    /// @notice Magic value indicating a valid signature (from IERC1271)
    bytes4 constant MAGICVALUE = 0x1626ba7e;

    /// @notice Magic value indicating a failed signature (from IERC1271)
    bytes4 constant FAILVALUE = 0xffffffff;

    error SpendTokenWithdrawAssetMismatch(address spendToken, address withdrawAsset);
    error SpendValueWithdrawAmountMismatch(uint256 spendValue, uint256 withdrawAmount);
    error InvalidWithdrawRequestNonce(uint128 noncePostfix, uint128 permissionHashPostfix);

    // /// @notice The hash is not the current payment details hash being processed in PaymentEscrow
    // error InvalidHash();

    /// @notice Constructor to set the PaymentEscrow contract address
    /// @param _paymentEscrow Address of the PaymentEscrow contract
    constructor(PaymentEscrow _paymentEscrow, MagicSpend _magicSpend) {
        paymentEscrow = _paymentEscrow;
        magicSpend = address(_magicSpend);
    }

    /// @notice Implementation of IERC1271 isValidSignature
    /// @dev Behavior depends on whether we need to intentionally trigger a failure to invoke the ERC-6492 prepareData
    /// flow.
    ///      If the criteria required to process the given token type is not already met, we fail intentionally.
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        // Get current spend permission values from PaymentEscrow
        address currentAccount = paymentEscrow.getCurrentBuyer();
        uint256 currentValue = paymentEscrow.getCurrentValue();
        address currentToken = paymentEscrow.getCurrentToken();

        // bytes32 rawPaymentDetailsHash = paymentEscrow.getCurrentPermissionHash();
        // console2.log("Current permission hash from PaymentEscrow:", uint256(rawPaymentDetailsHash));
        // bytes32 expectedHash = CoinbaseSmartWallet(payable(currentAccount)).replaySafeHash(rawPaymentDetailsHash);
        // console2.log("Expected replay-safe hash:", uint256(expectedHash));
        // if (hash != expectedHash) revert InvalidHash();

        // if the current buyer's account balance is less than the current value, we need to submit the
        // magic spend request, therefore return fail value to trigger the ERC-6492 prepareData flow.
        if (IERC20(currentToken).balanceOf(currentAccount) < currentValue) {
            return FAILVALUE;
        }

        return CoinbaseSmartWallet(payable(currentAccount)).isValidSignature(hash, signature);
    }

    function performWithdraw(uint256 value, MagicSpend.WithdrawRequest calldata withdrawRequest) external {
        // TODO: we might need to check the msg.sender here, but it would be the publicERC6492Validator....
        // we might need a private erc 6492 validator that only takes orders from paymentEscrow....
        address currentToken = paymentEscrow.getCurrentToken();
        uint256 currentValue = paymentEscrow.getCurrentValue();
        address currentAccount = paymentEscrow.getCurrentBuyer();
        bytes32 paymentDetailsHash = paymentEscrow.getCurrentDetailsHash();

        // check spend token and withdraw asset are the same
        if (currentToken != withdrawRequest.asset) {
            revert SpendTokenWithdrawAssetMismatch(currentToken, withdrawRequest.asset);
        }

        // check spend value is the same as what's being processed in PaymentEscrow
        if (value != currentValue) {
            revert SpendValueWithdrawAmountMismatch(value, currentValue);
        }

        // check spend value is not less than withdraw request amount
        if (withdrawRequest.amount > value) {
            revert SpendValueWithdrawAmountMismatch(value, withdrawRequest.amount);
        }

        // check withdraw request nonce postfix matches payment details hash postfix.
        if (uint128(withdrawRequest.nonce) != uint128(uint256(paymentDetailsHash))) {
            revert InvalidWithdrawRequestNonce(uint128(withdrawRequest.nonce), uint128(uint256(paymentDetailsHash)));
        }

        _execute({
            account: currentAccount,
            target: magicSpend,
            value: 0,
            data: abi.encodeWithSelector(MagicSpend.withdraw.selector, withdrawRequest)
        });
    }

    function _execute(address account, address target, uint256 value, bytes memory data) internal virtual {
        CoinbaseSmartWallet(payable(account)).execute({target: target, value: value, data: data});
    }
}
