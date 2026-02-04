pragma solidity ^0.8.0;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {UserOperationLib} from "account-abstraction/core/UserOperationLib.sol";
import {Eip7702Support} from "account-abstraction/core/Eip7702Support.sol";
import {IERC5267} from "../interfaces/IERC5267.sol";
import {ValidityFormatMismatch} from "../types/Error.sol";

library Lib4337 {
    /// @dev Highest bit of uint48, indicates block number mode when set on both validAfter and validUntil
    uint48 internal constant MODE_BIT = 0x800000000000;
    bytes32 internal constant _DOMAIN_TYPEHASH_SANS_CHAIN_ID =
        0x91ab3d17e3a50a9d89e63fd30b92be7f5336b03b287bb946787a83a9d62a2766;

    function chainAgnosticUserOpHash(address ep, PackedUserOperation calldata userOp) external view returns (bytes32) {
        bytes32 overrideInitCodeHash = Eip7702Support._getEip7702InitCodeHashOverride(userOp);
        return _hashTypedDataSansChainId(ep, UserOperationLib.hash(userOp, overrideInitCodeHash));
    }

    function parseValidationData(uint256 validationData)
        internal
        pure
        returns (uint48 validAfter, uint48 validUntil, address result)
    {
        assembly {
            result := validationData
            validUntil := and(shr(160, validationData), 0xffffffffffff)
            switch iszero(validUntil)
            case 1 { validUntil := 0xffffffffffff }
            validAfter := shr(208, validationData)
        }
    }

    function checkValidation(uint256 validationData) internal view returns (bool) {
        (uint48 vAfter, uint48 vUntil, address res) = Lib4337.parseValidationData(validationData);
        if (vAfter > block.timestamp || vUntil < block.timestamp) {
            return false;
        }
        return res == address(0);
    }

    /// @dev Variant of `_hashTypedData` that excludes the chain ID.
    /// Included for the niche use case of cross-chain workflows.
    function _hashTypedDataSansChainId(address addr, bytes32 structHash) internal view returns (bytes32 digest) {
        (, string memory name, string memory version,,,,) = IERC5267(addr).eip712Domain();
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40) // Load the free memory pointer.
            mstore(0x00, _DOMAIN_TYPEHASH_SANS_CHAIN_ID)
            mstore(0x20, keccak256(add(name, 0x20), mload(name)))
            mstore(0x40, keccak256(add(version, 0x20), mload(version)))
            mstore(0x60, addr)
            // Compute the digest.
            mstore(0x20, keccak256(0x00, 0x80)) // Store the domain separator.
            mstore(0x00, 0x1901) // Store "\x19\x01".
            mstore(0x40, structHash) // Store the struct hash.
            digest := keccak256(0x1e, 0x42)
            mstore(0x40, m) // Restore the free memory pointer.
            mstore(0x60, 0) // Restore the zero pointer.
        }
    }

    function intersectValidationData(uint256 a, uint256 b) internal pure returns (uint256 validationData) {
        return _intersectValidationData(a, b);
    }

    /// @dev Returns true if validation data uses block number format (both validAfter and validUntil have MODE_BIT set)
    function _usesBlockNumberFormat(uint48 validAfter, uint48 validUntil) internal pure returns (bool) {
        return (validAfter & MODE_BIT != 0) && (validUntil & MODE_BIT != 0);
    }

    function _intersectValidationData(uint256 preValidationData, uint256 validationRes)
        internal
        pure
        returns (uint256 resValidationData)
    {
        if (preValidationData == 0 || validationRes == 0) {
            return preValidationData | validationRes;
        }

        // Extract raw time bounds
        uint48 validUntil1 = uint48(preValidationData >> 160);
        uint48 validUntil2 = uint48(validationRes >> 160);
        uint48 validAfter1 = uint48(preValidationData >> 208);
        uint48 validAfter2 = uint48(validationRes >> 208);

        // Check for validity format mismatch (EP v0.9: block number vs timestamp)
        // Block number format: both validAfter and validUntil have highest bit set
        bool preUsesBlock = _usesBlockNumberFormat(validAfter1, validUntil1);
        bool resUsesBlock = _usesBlockNumberFormat(validAfter2, validUntil2);
        if (preUsesBlock != resUsesBlock) revert ValidityFormatMismatch();

        // Convert validUntil=0 to max (no expiry)
        if (validUntil1 == 0) validUntil1 = type(uint48).max;
        if (validUntil2 == 0) validUntil2 = type(uint48).max;

        resValidationData = uint256(validUntil1 > validUntil2 ? validUntil2 : validUntil1) << 160;
        resValidationData |= uint256(validAfter1 < validAfter2 ? validAfter2 : validAfter1) << 208;

        // Aggregator values: 0 = success, 1 = failure, >1 = aggregator address
        //
        // Rules (in precedence order):
        // 1. Any failure (1) → fail
        // 2. Both success (0) → success
        // 3. Aggregator + success → preserve aggregator (SECURITY CRITICAL)
        // 4. Success + aggregator → adopt aggregator
        // 5. Same aggregator → keep it
        // 6. Different aggregators → fail (cannot satisfy both)
        uint160 preAgg = uint160(preValidationData);
        uint160 resAgg = uint160(validationRes);

        uint160 finalAgg;

        finalAgg = (preAgg == 1 || resAgg == 1)
            ? 1  // Any failure
            : (preAgg == 0 && resAgg == 0)
                ? 0  // Both success
                : (preAgg > 1 && resAgg == 0)
                    ? preAgg  // Preserve aggregator (FIX)
                    : (preAgg == 0 && resAgg > 1)
                        ? resAgg  // Use new aggregator
                        : (preAgg == resAgg)
                            ? preAgg  // Same aggregator
                            : 1; // Conflict or unknown

        resValidationData |= finalAgg;
    }
}
