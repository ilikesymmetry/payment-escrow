// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

/// @dev ERC-3009 does not actually support this method, but it should.
/// @dev We should use this opportunity to change the standard to use generic signatures this time.
/// @dev USDC and EURC use this interface without it being an official standard yet.
/// @dev Reverts if signature validation fails.
interface ERC3009 {
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes memory signature
    ) external;
}
