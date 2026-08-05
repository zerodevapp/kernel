// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {UserOperationLib} from "account-abstraction/core/UserOperationLib.sol";
import {Eip7702Support} from "account-abstraction/core/Eip7702Support.sol";
import {IERC5267} from "../interfaces/IERC5267.sol";
import {DOMAIN_TYPEHASH_SANS_CHAIN_ID} from "../types/Constants.sol";
import {ValidityFormatMismatch} from "../types/Error.sol";

library Lib4337 {
    /// @dev EntryPoint v0.9 flag for block number mode.
    uint48 internal constant MODE_BIT = 0x800000000000;

    function chainAgnosticUserOpHash(address ep, PackedUserOperation calldata userOp) internal view returns (bytes32) {
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
        if (validationData == 0) {
            return true;
        }
        (uint48 vAfter, uint48 vUntil, address res) = Lib4337.parseValidationData(validationData);
        uint256 current;
        if (_usesBlockNumberFormat(vAfter, vUntil)) {
            vAfter &= MODE_BIT - 1;
            vUntil &= MODE_BIT - 1;
            current = block.number;
        } else {
            current = block.timestamp;
        }
        // Canonical EntryPoint v0.9 interval: (validAfter, validUntil].
        return res == address(0) && current > vAfter && current <= vUntil;
    }

    /// @dev Variant of `_hashTypedData` that excludes the chain ID.
    /// Included for the niche use case of cross-chain workflows.
    function _hashTypedDataSansChainId(address addr, bytes32 structHash) internal view returns (bytes32 digest) {
        (, string memory name, string memory version,,,,) = IERC5267(addr).eip712Domain();
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40) // Load the free memory pointer.
            mstore(0x00, DOMAIN_TYPEHASH_SANS_CHAIN_ID)
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

    /// @dev Returns true if validation data uses block number format per EntryPoint v0.9.
    function _usesBlockNumberFormat(uint48 validAfter, uint48 validUntil) internal pure returns (bool) {
        return validAfter > MODE_BIT && validUntil > MODE_BIT;
    }

    function _intersectValidationData(uint256 preValidationData, uint256 validationRes)
        internal
        pure
        returns (uint256 resValidationData)
    {
        if (preValidationData == 0 || validationRes == 0) {
            return preValidationData | validationRes;
        }

        // Aggregator FIRST: resolve success / failure / conflict before touching the ranges.
        //
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

        uint160 finalAgg = (preAgg == 1 || resAgg == 1)
            ? 1  // Any failure
            : (preAgg == 0 && resAgg == 0)
                ? 0  // Both success
                : (preAgg > 1 && resAgg == 0)
                    ? preAgg  // Preserve aggregator
                    : (preAgg == 0 && resAgg > 1)
                        ? resAgg  // Use new aggregator
                        : (preAgg == resAgg)
                            ? preAgg  // Same aggregator
                            : 1; // Conflict or unknown

        // Extract raw time bounds
        uint48 validUntil1 = uint48(preValidationData >> 160);
        uint48 validUntil2 = uint48(validationRes >> 160);
        uint48 validAfter1 = uint48(preValidationData >> 208);
        uint48 validAfter2 = uint48(validationRes >> 208);

        // Normalize validUntil=0 to max (no expiry) BEFORE classifying the format. Doing this
        // after the format check misclassifies an unbounded block range (validUntil=0) as a
        // timestamp range, letting a mixed intersection drop a future timestamp start.
        if (validUntil1 == 0) validUntil1 = type(uint48).max;
        if (validUntil2 == 0) validUntil2 = type(uint48).max;

        // Only enforce format compatibility for a usable (non-failure) result. When either side
        // reports signature failure (finalAgg == 1) the op is rejected regardless of its time
        // bounds, and a failed operand carries zeroed bounds that must not trigger a spurious
        // ValidityFormatMismatch revert — so the check is skipped. A neutral [0, max] range
        // carries no restriction and no format and is likewise exempt (its normalized validUntil
        // has MODE_BIT set, which would otherwise misclassify it as a block range).
        if (finalAgg != 1) {
            bool preNeutral = validAfter1 == 0 && validUntil1 == type(uint48).max;
            bool resNeutral = validAfter2 == 0 && validUntil2 == type(uint48).max;
            // Block number format: both validAfter and validUntil have the highest bit set.
            if (!preNeutral && !resNeutral) {
                require(
                    _usesBlockNumberFormat(validAfter1, validUntil1)
                        == _usesBlockNumberFormat(validAfter2, validUntil2),
                    ValidityFormatMismatch()
                );
            }
        }

        resValidationData = uint256(validUntil1 > validUntil2 ? validUntil2 : validUntil1) << 160;
        resValidationData |= uint256(validAfter1 < validAfter2 ? validAfter2 : validAfter1) << 208;
        resValidationData |= finalAgg;
    }
}
