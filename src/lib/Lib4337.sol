pragma solidity ^0.8.0;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {UserOperationLib} from "account-abstraction/core/UserOperationLib.sol";
import {Eip7702Support} from "account-abstraction/core/Eip7702Support.sol";
import {ERC1271_MAGICVALUE, SIG_VALIDATION_FAILED_UINT} from "../types/Constants.sol";
import {ValidationData} from "../types/Types.sol";
import {IERC5267} from "../interfaces/IERC5267.sol";

library Lib4337 {
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

    function intersectValidationData(uint256 a, bytes4 res) internal pure returns (uint256) {
        return _intersectValidationData(a, signatureResultToValidationData(res));
    }

    function intersectValidationData(uint256 a, uint256 b) internal pure returns (uint256 validationData) {
        return _intersectValidationData(a, b);
    }

    function _intersectValidationData(uint256 a, uint256 b) private pure returns (uint256 validationData) {
        assembly {
            // xor(a,b) == shows only matching bits
            // and(xor(a,b), 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff) == filters out the validAfter and validUntil bits
            // if the result is not zero, then aggregator part is not matching
            // validCase :
            // a == 0 || b == 0 || xor(a,b) == 0
            // invalidCase :
            // a mul b != 0 && xor(a,b) != 0
            let sum := shl(96, add(a, b))
            switch or(
                iszero(and(xor(a, b), 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff)),
                or(eq(sum, shl(96, a)), eq(sum, shl(96, b)))
            )
            case 1 {
                validationData := and(or(a, b), 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff)
                // validAfter
                let a_vd := and(0xffffffffffff0000000000000000000000000000000000000000000000000000, a)
                let b_vd := and(0xffffffffffff0000000000000000000000000000000000000000000000000000, b)
                validationData := or(validationData, xor(a_vd, mul(xor(a_vd, b_vd), gt(b_vd, a_vd))))
                // validUntil
                a_vd := and(0x000000000000ffffffffffff0000000000000000000000000000000000000000, a)
                if iszero(a_vd) { a_vd := 0x000000000000ffffffffffff0000000000000000000000000000000000000000 }
                b_vd := and(0x000000000000ffffffffffff0000000000000000000000000000000000000000, b)
                if iszero(b_vd) { b_vd := 0x000000000000ffffffffffff0000000000000000000000000000000000000000 }
                let until := xor(a_vd, mul(xor(a_vd, b_vd), lt(b_vd, a_vd)))
                if iszero(until) { until := 0x000000000000ffffffffffff0000000000000000000000000000000000000000 }
                validationData := or(validationData, until)
            }
            default { validationData := SIG_VALIDATION_FAILED_UINT }
        }
    }

    function signatureResultToValidationData(bytes4 res) public pure returns (uint256 validationData) {
        return res == ERC1271_MAGICVALUE ? 0 : 1;
    }
}
