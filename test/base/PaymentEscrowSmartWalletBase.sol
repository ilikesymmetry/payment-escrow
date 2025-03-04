// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {PaymentEscrowBase} from "./PaymentEscrowBase.sol";
import {Test, console2} from "forge-std/Test.sol";

import {CoinbaseSmartWallet} from "smart-wallet/CoinbaseSmartWallet.sol";
import {CoinbaseSmartWalletFactory} from "smart-wallet/CoinbaseSmartWalletFactory.sol";
import {PaymentEscrow} from "src/PaymentEscrow.sol";

contract PaymentEscrowSmartWalletBase is PaymentEscrowBase {
    // Constants for EIP-6492 support
    bytes32 constant EIP6492_MAGIC_VALUE = 0x6492649264926492649264926492649264926492649264926492649264926492;
    bytes32 constant CBSW_MESSAGE_TYPEHASH = keccak256("CoinbaseSmartWalletMessage(bytes32 hash)");

    // Smart wallet specific state
    CoinbaseSmartWalletFactory public smartWalletFactory;
    address public smartWalletImplementation;
    address public smartWalletBuyer; // The counterfactual address
    CoinbaseSmartWallet public helperWallet; // Helper instance for using smart wallet functions
    uint256 internal constant SMART_WALLET_OWNER_PK = 0x5678; // Different from BUYER_PK

    function setUp() public virtual override {
        super.setUp();

        // Deploy the implementation and factory
        smartWalletImplementation = address(new CoinbaseSmartWallet());
        smartWalletFactory = new CoinbaseSmartWalletFactory(smartWalletImplementation);

        // Create and initialize helper wallet through factory
        address smartWalletOwner = vm.addr(SMART_WALLET_OWNER_PK);
        bytes[] memory helperOwners = new bytes[](1);
        helperOwners[0] = abi.encode(smartWalletOwner);
        helperWallet = CoinbaseSmartWallet(payable(smartWalletFactory.createAccount(helperOwners, 0)));

        // Generate the counterfactual smart wallet address
        smartWalletBuyer = smartWalletFactory.getAddress(helperOwners, 0);

        // Fund the smart wallet buyer
        token.mint(smartWalletBuyer, 1000e6);
    }

    function _sign(uint256 pk, bytes32 hash) internal pure returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);
        return abi.encodePacked(r, s, v);
    }

    function _signSmartWalletERC3009(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint256 ownerPk,
        uint256 ownerIndex
    ) internal view returns (bytes memory) {
        // Get the PaymentEscrow hash first
        PaymentEscrow.Authorization memory auth = PaymentEscrow.Authorization({
            token: address(token),
            from: from,
            to: to,
            validAfter: validAfter,
            validBefore: validBefore,
            extraData: PaymentEscrow.ExtraData({
                salt: uint256(nonce),
                operator: operator,
                merchant: merchant,
                feeBps: FEE_BPS,
                feeRecipient: feeRecipient
            })
        });
        bytes32 paymentHash = keccak256(abi.encode(auth));

        // Construct replaySafeHash without relying on the account contract being deployed
        bytes32 cbswDomainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("Coinbase Smart Wallet")),
                keccak256(bytes("1")),
                block.chainid,
                from // The counterfactual wallet address
            )
        );
        console2.log("Domain separator:", uint256(cbswDomainSeparator));
        console2.log("Message typehash:", uint256(CBSW_MESSAGE_TYPEHASH));
        console2.log("Verifying contract:", from);
        console2.log("Expected signer:", vm.addr(ownerPk));
        console2.log("Payment hash:", uint256(paymentHash));

        bytes32 smartWalletHash = keccak256(abi.encode(CBSW_MESSAGE_TYPEHASH, paymentHash));
        console2.log("Smart wallet hash:", uint256(smartWalletHash));

        bytes32 replaySafeHash = keccak256(
            abi.encodePacked("\x19\x01", cbswDomainSeparator, keccak256(abi.encode(CBSW_MESSAGE_TYPEHASH, paymentHash)))
        );
        console2.log("Replay safe hash:", uint256(replaySafeHash));

        // Sign the replay-safe hash and wrap with owner index
        bytes memory signature = _sign(ownerPk, replaySafeHash);
        bytes memory wrappedSignature =
            abi.encode(CoinbaseSmartWallet.SignatureWrapper({ownerIndex: ownerIndex, signatureData: signature}));

        // Wrap in EIP-6492 format
        bytes[] memory initialOwners = new bytes[](1);
        initialOwners[0] = abi.encode(vm.addr(ownerPk));

        address factory = address(smartWalletFactory);
        bytes memory factoryCallData = abi.encodeWithSignature("createAccount(bytes[],uint256)", initialOwners, 0);
        bytes memory eip6492Signature = abi.encode(factory, factoryCallData, wrappedSignature);
        return abi.encodePacked(eip6492Signature, EIP6492_MAGIC_VALUE);
    }

    function _createSmartWalletPaymentDetails(uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce)
        internal
        view
        returns (bytes memory)
    {
        PaymentEscrow.Authorization memory auth = PaymentEscrow.Authorization({
            token: address(token),
            from: smartWalletBuyer, // Use smart wallet address instead of EOA
            to: address(paymentEscrow),
            validAfter: validAfter,
            validBefore: validBefore,
            extraData: PaymentEscrow.ExtraData({
                salt: uint256(nonce),
                operator: operator,
                merchant: merchant,
                feeBps: FEE_BPS,
                feeRecipient: feeRecipient
            })
        });
        return abi.encode(auth);
    }
}
