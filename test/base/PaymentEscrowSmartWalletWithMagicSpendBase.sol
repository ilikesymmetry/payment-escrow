// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {PaymentEscrow} from "../../src/PaymentEscrow.sol";
import {PaymentEscrowSmartWalletBase} from "./PaymentEscrowSmartWalletBase.sol";
import {MagicSpend} from "magic-spend/MagicSpend.sol";
import {MagicSpendHook} from "../../src/MagicSpendHook.sol";
import {CoinbaseSmartWallet} from "smart-wallet/CoinbaseSmartWallet.sol";

contract PaymentEscrowSmartWalletWithMagicSpendBase is PaymentEscrowSmartWalletBase {
    MagicSpend public magicSpend;
    MagicSpendHook public magicSpendHook;
    uint128 constant NONCE_HASH_BITS = 128;
    uint256 constant MAGIC_SPEND_OWNER_PK = 0x1234;

    function setUp() public virtual override {
        super.setUp();

        // We skip funding the smart wallet so we don't have enough tokens for the charge.

        // Deploy MagicSpend and Hook
        address magicSpendOwner = vm.addr(MAGIC_SPEND_OWNER_PK);
        magicSpend = new MagicSpend(magicSpendOwner, 100000000000);
        magicSpendHook = new MagicSpendHook(paymentEscrow, magicSpend);

        // Add hook as owner to deployed wallet
        vm.prank(deployedWalletOwner);
        CoinbaseSmartWallet(payable(smartWalletDeployed)).addOwnerAddress(address(magicSpendHook));
    }

    function _createWithdrawRequest(bytes32 paymentDetailsHash, uint128 nonceEntropy)
        internal
        view
        returns (MagicSpend.WithdrawRequest memory)
    {
        // Extract lower 128 bits of payment details hash
        uint128 hashPortion = uint128(uint256(paymentDetailsHash));

        // Combine hash portion and entropy portion
        uint256 nonce = (uint256(nonceEntropy) << NONCE_HASH_BITS) | hashPortion;

        return MagicSpend.WithdrawRequest({
            asset: address(mockERC3009Token),
            amount: 0, // Will be set by caller
            nonce: nonce,
            expiry: type(uint48).max,
            signature: hex""
        });
    }

    function _signWithdrawRequest(address account, MagicSpend.WithdrawRequest memory withdrawRequest, uint256 ownerPk)
        internal
        view
        returns (bytes memory)
    {
        bytes32 hash = magicSpend.getHash(account, withdrawRequest);
        return _sign(MAGIC_SPEND_OWNER_PK, hash);
    }

    function _signSmartWalletERC3009WithMagicSpend(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        uint256 ownerPk,
        uint256 ownerIndex,
        uint128 nonceEntropy
    ) internal view returns (bytes memory) {
        // First get the normal smart wallet signature
        bytes memory signature = _signSmartWalletERC3009(from, to, value, validAfter, validBefore, ownerPk, ownerIndex);

        // Create and sign withdraw request
        bytes32 paymentDetailsHash = keccak256(
            abi.encode(
                PaymentEscrow.Authorization({
                    token: address(mockERC3009Token),
                    from: from,
                    to: to,
                    validAfter: validAfter,
                    validBefore: validBefore,
                    extraData: PaymentEscrow.ExtraData({
                        salt: 0,
                        operator: operator,
                        merchant: merchant,
                        feeBps: FEE_BPS,
                        feeRecipient: feeRecipient
                    })
                })
            )
        );

        MagicSpend.WithdrawRequest memory withdrawRequest = _createWithdrawRequest(paymentDetailsHash, nonceEntropy);
        withdrawRequest.amount = value;
        withdrawRequest.signature = _signWithdrawRequest(from, withdrawRequest, ownerPk);

        // Wrap in ERC6492 format with performWithdraw call
        bytes memory hookCallData = abi.encodeCall(MagicSpendHook.performWithdraw, (value, withdrawRequest));

        return abi.encodePacked(abi.encode(address(magicSpendHook), hookCallData, signature), EIP6492_MAGIC_VALUE);
    }
}
