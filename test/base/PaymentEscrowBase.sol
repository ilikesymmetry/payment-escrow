// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";
import {PaymentEscrow} from "../../src/PaymentEscrow.sol";
import {IERC3009} from "../../src/IERC3009.sol";
import {MockERC3009Token} from "../mocks/MockERC3009Token.sol";

contract PaymentEscrowBase is Test {
    PaymentEscrow public paymentEscrow;
    MockERC3009Token public token;

    address public operator;
    address public merchant;
    address public buyer;
    address public feeRecipient;
    uint16 constant FEE_BPS = 100; // 1%
    uint256 internal constant BUYER_PK = 0x1234;

    function setUp() public virtual {
        paymentEscrow = new PaymentEscrow();
        token = new MockERC3009Token("Mock USDC", "mUSDC", 6);

        operator = makeAddr("operator");
        merchant = makeAddr("merchant");
        buyer = vm.addr(BUYER_PK); // Derive address from private key
        feeRecipient = makeAddr("feeRecipient");

        token.mint(buyer, 1000e6);
    }

    function _signERC3009(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint256 signerPk
    ) internal view returns (bytes memory) {
        console2.log("From:", from);
        console2.log("To:", to);
        console2.log("Value:", value);
        console2.log("ValidAfter:", validAfter);
        console2.log("ValidBefore:", validBefore);
        console2.log("Nonce:", uint256(nonce));

        bytes32 structHash = keccak256(
            abi.encode(token.RECEIVE_WITH_AUTHORIZATION_TYPEHASH(), from, to, value, validAfter, validBefore, nonce)
        );

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structHash));

        // Add debug logs
        console2.log("Signing digest:", uint256(digest));
        console2.log("Domain separator:", uint256(token.DOMAIN_SEPARATOR()));
        console2.log("Struct hash:", uint256(structHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _createPaymentDetails(uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce)
        internal
        view
        returns (bytes memory)
    {
        PaymentEscrow.Authorization memory auth = PaymentEscrow.Authorization({
            token: address(token),
            from: buyer,
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

    function _getValidTimeRange() internal view returns (uint256 validAfter, uint256 validBefore) {
        validAfter = block.timestamp - 1;
        validBefore = block.timestamp + 1 days;
    }
}
