// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Kernel, Install} from "./Kernel.sol";
import {KernelUUPS} from "./KernelUUPS.sol";
import {KernelImmutableECDSA} from "./KernelImmutableECDSA.sol";
import {LibClone} from "solady/utils/LibClone.sol";
import {EfficientHashLib} from "solady/utils/EfficientHashLib.sol";
import {InvalidSigner, ImplementationNotDeployed} from "./types/Error.sol";
import {KernelDeployed} from "./types/Events.sol";

/// @title KernelFactory
/// @author taek <leekt216@gmail.com>
/// @notice Factory for deterministic deployment of Kernel smart accounts using ERC-1967 proxies.
contract KernelFactory {
    KernelUUPS public immutable UUPS;
    KernelImmutableECDSA public immutable IMMUTABLE_ECDSA;

    constructor(KernelUUPS _uups, KernelImmutableECDSA _immutableEcdsa) {
        require(address(_uups).code.length > 0 && address(_immutableEcdsa).code.length > 0, ImplementationNotDeployed());
        UUPS = _uups;
        IMMUTABLE_ECDSA = _immutableEcdsa;
    }

    /// @notice Deploys a new UUPS Kernel account or returns the existing one at the deterministic address.
    /// @param initialPackages The module install packages for initialization; the first becomes root validator.
    /// @param nonce A deployment nonce for salt derivation.
    /// @return The deployed Kernel account.
    function deploy(Install[] calldata initialPackages, uint256 nonce) external payable returns (Kernel) {
        bytes32 salt = _calculateSalt(initialPackages, nonce);
        (bool alreadyDeployed, address account) = LibClone.createDeterministicERC1967(msg.value, address(UUPS), salt);
        Kernel k = Kernel(payable(account));
        if (!alreadyDeployed) {
            k.initialize(initialPackages);
            emit KernelDeployed(account);
        }
        return k;
    }

    /// @notice Computes the deterministic address for a UUPS Kernel deployment.
    /// @param initialPackages The module install packages used for salt derivation.
    /// @param nonce A deployment nonce for salt derivation.
    /// @return The predicted deployment address.
    function getAddress(Install[] calldata initialPackages, uint256 nonce) public view virtual returns (address) {
        bytes32 salt = _calculateSalt(initialPackages, nonce);
        return LibClone.predictDeterministicAddressERC1967(address(UUPS), salt, address(this));
    }

    /// @notice Deploys a Kernel account with an immutable ECDSA fallback signer.
    /// @dev Uses ERC-1967 clones with immutable args to store the signer address.
    /// @param signer The ECDSA signer address stored immutably in the clone; must not be address(0).
    /// @param initialPackages The module install packages for initialization.
    /// @param nonce A deployment nonce for salt derivation.
    /// @return The deployed Kernel account.
    /// forge-lint: disable-next-line(mixed-case-function)
    function deployECDSA(address signer, Install[] calldata initialPackages, uint256 nonce)
        external
        payable
        returns (Kernel)
    {
        require(signer != address(0), InvalidSigner());
        bytes32 salt = _calculateSalt(initialPackages, nonce);
        (bool alreadyDeployed, address account) =
            LibClone.createDeterministicERC1967(msg.value, address(IMMUTABLE_ECDSA), abi.encodePacked(signer), salt);
        Kernel k = Kernel(payable(account));
        if (!alreadyDeployed) {
            k.initialize(initialPackages);
            emit KernelDeployed(account);
        }
        return k;
    }

    /// @notice Computes the deterministic address for an immutable ECDSA Kernel deployment.
    /// @param signer The ECDSA signer address.
    /// @param initialPackages The module install packages used for salt derivation.
    /// @param nonce A deployment nonce for salt derivation.
    /// @return The predicted deployment address.
    /// forge-lint: disable-next-line(mixed-case-function)
    function getECDSAAddress(address signer, Install[] calldata initialPackages, uint256 nonce)
        public
        view
        virtual
        returns (address)
    {
        bytes32 salt = _calculateSalt(initialPackages, nonce);
        return LibClone.predictDeterministicAddressERC1967(
            address(IMMUTABLE_ECDSA), abi.encodePacked(signer), salt, address(this)
        );
    }

    /// @notice Computes a deterministic salt from the install packages and nonce.
    /// @param initialPackages The module install packages.
    /// @param nonce A deployment nonce.
    /// @return The computed salt hash.
    function _calculateSalt(Install[] calldata initialPackages, uint256 nonce) internal pure returns (bytes32) {
        unchecked {
            bytes32[] memory buffer = EfficientHashLib.malloc(initialPackages.length + 1);
            EfficientHashLib.set(buffer, 0, nonce);
            for (uint256 i = 1; i < buffer.length; i++) {
                Install calldata pkg = initialPackages[i - 1];
                EfficientHashLib.set(
                    buffer,
                    i,
                    EfficientHashLib.hash(
                        bytes32(pkg.moduleType),
                        bytes32(uint256(uint160(pkg.module))),
                        EfficientHashLib.hashCalldata(pkg.moduleData),
                        EfficientHashLib.hashCalldata(pkg.internalData)
                    )
                );
            }
            return EfficientHashLib.hash(buffer);
        }
    }
}
