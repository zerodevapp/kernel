pragma solidity ^0.8.0;

import {Kernel, Install} from "./Kernel.sol";
import {KernelUUPS} from "./KernelUUPS.sol";
import {KernelImmutableECDSA} from "./KernelImmutableECDSA.sol";
import {LibClone} from "solady/utils/LibClone.sol";
import {EfficientHashLib} from "solady/utils/EfficientHashLib.sol";

contract KernelFactory {
    error InvalidSigner();

    KernelUUPS public immutable UUPS;
    KernelImmutableECDSA public immutable IMMUTABLE_ECDSA;

    constructor(KernelUUPS _uups, KernelImmutableECDSA _immutableEcdsa) {
        UUPS = _uups;
        IMMUTABLE_ECDSA = _immutableEcdsa;
    }

    // Kernel UUPS
    function deploy(Install[] calldata initialPackages, uint256 nonce) external payable returns (Kernel) {
        bytes32 salt = _calculateSalt(initialPackages, nonce);
        (bool deployed, address account) = LibClone.createDeterministicERC1967(msg.value, address(UUPS), salt);
        Kernel k = Kernel(payable(account));
        if (deployed) {
            return k;
        }
        k.initialize(initialPackages);
        return k;
    }

    function getAddress(Install[] calldata initialPackages, uint256 nonce) public view virtual returns (address) {
        bytes32 salt = _calculateSalt(initialPackages, nonce);
        return LibClone.predictDeterministicAddressERC1967(address(UUPS), salt, address(this));
    }

    // Kernel UUPS ECDSA fallback
    /// forge-lint: disable-next-line(mixed-case-function)
    function deployECDSA(address signer, Install[] calldata initialPackages, uint256 nonce)
        external
        payable
        returns (Kernel)
    {
        require(signer != address(0), InvalidSigner());
        bytes32 salt = _calculateSalt(initialPackages, nonce);
        (bool deployed, address account) =
            LibClone.createDeterministicERC1967(msg.value, address(IMMUTABLE_ECDSA), abi.encodePacked(signer), salt);
        Kernel k = Kernel(payable(account));
        if (!deployed) {
            k.initialize(initialPackages);
        }
        return k;
    }

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
