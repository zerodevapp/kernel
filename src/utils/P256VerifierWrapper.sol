// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {FCL_ecdsa} from "FreshCryptoLib/FCL_ecdsa.sol";

/// @title P256VerifierWrapper
/// @author rdubois-crypto
/// @author KONFeature
/// @notice Wrapper arround the P256Verifier contract of @rdubois-crypto, using it to accept EIP-7212 compliant verification (p256 pre-compiled curve)
/// @dev This lib is only a wrapper around the P256Verifier contract.
///     It will call the verifySignature function of the P256Verifier contract.
///     Once the RIP-7212 will be deployed and effective, this contract will be useless.
///     Tracker on polygon: PR: https://github.com/maticnetwork/bor/pull/1069
///                         Now waiting on the Napoli hardfork to be deployed
contract P256VerifierWrapper {
    /**
     * Precompiles don't use a function signature. The first byte of callldata
     * is the first byte of an input argument. In this case:
     *
     * input[  0: 32] = signed data hash
     * input[ 32: 64] = signature r
     * input[ 64: 96] = signature s
     * input[ 96:128] = public key x
     * input[128:160] = public key y
     *
     * result[ 0: 32] = 0x00..00 (invalid) or 0x00..01 (valid)
     *
     * For details, see https://eips.ethereum.org/EIPS/eip-7212
     */
    fallback(bytes calldata input) external returns (bytes memory) {
        if (input.length != 160) {
            return abi.encodePacked(uint256(0));
        }

        bytes32 hash = bytes32(input[0:32]);
        uint256 r = uint256(bytes32(input[32:64]));
        uint256 s = uint256(bytes32(input[64:96]));
        uint256 x = uint256(bytes32(input[96:128]));
        uint256 y = uint256(bytes32(input[128:160]));

        uint256 ret = FCL_ecdsa.ecdsa_verify(hash, r, s, x, y) ? 1 : 0;

        return abi.encodePacked(ret);
    }
}
