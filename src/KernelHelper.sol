pragma solidity ^0.8.0;

import "./types/Structs.sol";
import {IERC5267} from "./interfaces/IERC5267.sol";
import "./lib/Utils.sol";

contract KernelHelper {
    /// @dev `keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")`.
    bytes32 internal constant _DOMAIN_TYPEHASH = 0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

    /// @dev `keccak256("EIP712Domain(string name,string version,address verifyingContract)")`.
    /// This is only used in `_hashTypedDataSansChainId`.
    bytes32 internal constant _DOMAIN_TYPEHASH_SANS_CHAIN_ID =
        0x91ab3d17e3a50a9d89e63fd30b92be7f5336b03b287bb946787a83a9d62a2766;

    function installDigest(address kernel, bool replayable, uint256 nonce, Install[] calldata packages)
        external
        view
        returns (bytes32 digest)
    {
        function(address, bytes32) internal view returns(bytes32) hashTypedData =
            replayable ? _hashTypedDataSansChainId : _hashTypedData;
        digest = hashTypedData(
            kernel,
            keccak256(
                abi.encode(
                    keccak256(
                        "InstallPackages(uint256 nonce,Install[] packages)Install(uint256 moduleType,address module,bytes moduleData,bytes internalData)"
                    ),
                    nonce,
                    _installHash(packages)
                )
            )
        );
    }

    function installAndExecuteDigest(
        address kernel,
        bytes32 mode,
        Call[] calldata calls,
        InstallAndExecute calldata opData
    ) external returns (bytes32) {
        function(address, bytes32) internal view returns(bytes32) hashTypedData =
            opData.replayable ? _hashTypedDataSansChainId : _hashTypedData;
        bytes32 digest = hashTypedData(
            kernel,
            keccak256(
                abi.encode(
                    keccak256(
                        "ExecuteWithInstall(bytes32 mode, bytes execData,uint256 nonce,Install[] packages)Install(uint256 moduleType,address module,bytes moduleData,bytes internalData)"
                    ),
                    mode,
                    keccak256(abi.encode(calls)),
                    opData.nonce,
                    _installHash(opData.packages)
                )
            )
        );
        return digest;
    }

    function _installHash(Install[] calldata packages) internal pure returns (bytes32) {
        bytes32[] memory packageHashes = new bytes32[](packages.length);
        for (uint256 i = 0; i < packages.length; i++) {
            Install calldata pkg = packages[i];
            packageHashes[i] = keccak256(
                abi.encode(
                    keccak256("Install(uint256 moduleType,address module,bytes moduleData,bytes internalData)"),
                    pkg.moduleType,
                    pkg.module,
                    calldataKeccak(pkg.moduleData),
                    calldataKeccak(pkg.internalData)
                )
            );
        }
        return keccak256(abi.encodePacked(packageHashes));
    }

    function _hashTypedDataSansChainId(address addr, bytes32 structHash) internal view returns (bytes32 digest) {
        string memory name = "Kernel";
        string memory version = "0.4.0";
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

    function _hashTypedData(address addr, bytes32 structHash) internal view virtual returns (bytes32 digest) {
        string memory name = "Kernel";
        string memory version = "0.4.0";
        bytes32 separator = keccak256(bytes(name));
        bytes32 versionHash = keccak256(bytes(version));
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40) // Load the free memory pointer.
            mstore(m, _DOMAIN_TYPEHASH)
            mstore(add(m, 0x20), separator) // Name hash.
            mstore(add(m, 0x40), versionHash)
            mstore(add(m, 0x60), chainid())
            mstore(add(m, 0x80), addr)
            digest := keccak256(m, 0xa0)
            // Compute the digest.
            mstore(0x00, 0x1901000000000000) // Store "\x19\x01".
            mstore(0x1a, digest) // Store the domain separator.
            mstore(0x3a, structHash) // Store the struct hash.
            digest := keccak256(0x18, 0x42)
            // Restore the part of the free memory slot that was overwritten.
            mstore(0x3a, 0)
        }
    }
}
