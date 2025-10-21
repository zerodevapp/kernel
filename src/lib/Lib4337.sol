pragma solidity ^0.8.0;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {UserOperationLib} from "account-abstraction/core/UserOperationLib.sol";
import {Eip7702Support} from "account-abstraction/core/Eip7702Support.sol";
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

    function intersectValidationData(uint256 a, uint256 b) internal pure returns (uint256 validationData) {
        return _intersectValidationData(a, b);
    }

    function _intersectValidationData(uint256 preValidationData, uint256 validationRes)
        private
        pure
        returns (uint256 resValidationData)
    {
        //short circuit
        unchecked {
            if (preValidationData * validationRes == 0) {
                return preValidationData | validationRes;
            }
        }
        // forge-lint: disable-next-line(unsafe-typecast)
        uint48 validUntil1 = uint48(preValidationData >> 160);
        if (validUntil1 == 0) {
            validUntil1 = type(uint48).max;
        }
        // forge-lint: disable-next-line(unsafe-typecast)
        uint48 validUntil2 = uint48(validationRes >> 160);
        if (validUntil2 == 0) {
            validUntil2 = type(uint48).max;
        }
        resValidationData = ((validUntil1 > validUntil2) ? uint256(validUntil2) << 160 : uint256(validUntil1) << 160);

        // forge-lint: disable-next-line(unsafe-typecast)
        uint48 validAfter1 = uint48(preValidationData >> 208);
        // forge-lint: disable-next-line(unsafe-typecast)
        uint48 validAfter2 = uint48(validationRes >> 208);

        resValidationData |= ((validAfter1 < validAfter2) ? uint256(validAfter2) << 208 : uint256(validAfter1) << 208);

        // forge-lint: disable-next-line(unsafe-typecast)
        resValidationData |= uint160(preValidationData) == 1 ? 1 : uint160(validationRes);
    }
}
