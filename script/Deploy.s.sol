// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";
import {Strings} from "openzeppelin-contracts/contracts/utils/Strings.sol";
import {SpendPermissionManager} from "spend-permissions/SpendPermissionManager.sol";

import {PaymentEscrow} from "../src/PaymentEscrow.sol";

/**
 * @notice Deploy the PaymentEscrow contract.
 *
 * forge script Deploy --account dev --sender $SENDER --rpc-url $BASE_SEPOLIA_RPC --broadcast -vvvv
 * --verify --verifier-url $SEPOLIA_BASESCAN_API --etherscan-api-key $BASESCAN_API_KEY
 */
contract Deploy is Script {
    function run() public {
        // https://github.com/coinbase/spend-permissions/releases/tag/v1.0.0
        address spendPermissionManager = 0xf85210B21cC50302F477BA56686d2019dC9b67Ad;

        vm.startBroadcast();

        new PaymentEscrow{salt: 0}(SpendPermissionManager(payable(spendPermissionManager)));

        vm.stopBroadcast();
    }
}
