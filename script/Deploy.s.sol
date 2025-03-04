// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";
import {PaymentEscrow} from "../src/PaymentEscrow.sol";
import {PublicERC6492Validator} from "spend-permissions/PublicERC6492Validator.sol";
/**
 * @notice Deploy the PaymentEscrow contract.
 *
 * forge script Deploy --account dev --sender $SENDER --rpc-url $BASE_SEPOLIA_RPC --broadcast -vvvv
 * --verify --verifier-url $SEPOLIA_BASESCAN_API --etherscan-api-key $BASESCAN_API_KEY
 */

contract Deploy is Script {
    function run() public {
        vm.startBroadcast();

        new PaymentEscrow{salt: 0}(address(new PublicERC6492Validator()));

        vm.stopBroadcast();
    }
}
