function isValidSignature(bytes32 hash, bytes memory signature) public view returns (bytes4) {
    console2.log("CoinbaseSmartWallet.isValidSignature called with hash:", uint256(hash));

    // Decode the signature wrapper
    (uint256 ownerIndex, bytes memory innerSignature) = abi.decode(signature, (uint256, bytes));
    console2.log("Decoded ownerIndex:", ownerIndex);
    console2.log("Inner signature length:", innerSignature.length);

    // Verify the signature is from the owner
    bytes32 replaySafeHash =
        keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), keccak256(abi.encode(MESSAGE_TYPEHASH, hash))));
    console2.log("Computed replaySafeHash:", uint256(replaySafeHash));

    address signer = _recoverSigner(replaySafeHash, innerSignature);
    console2.log("Recovered signer:", signer);
    console2.log("Expected owner:", owners[ownerIndex]);

    if (signer != owners[ownerIndex]) {
        return INVALID_SIGNATURE;
    }

    return VALID_SIGNATURE;
}
