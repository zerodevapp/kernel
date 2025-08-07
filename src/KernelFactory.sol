pragma solidity ^0.8.0;

import {Kernel, Install} from "./Kernel.sol";
import {KernelUUPS} from "./KernelUUPS.sol";
import {LibClone} from "solady/utils/LibClone.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

contract KernelFactory {
    KernelUUPS public immutable template;

    constructor(IEntryPoint _entryPoint) {
        template = new KernelUUPS(_entryPoint);
    }

    // Kernel UUPS
    function deploy(Install[] calldata initialPackages, uint256 nonce) external payable returns (Kernel) {
        bytes32 salt = keccak256(abi.encode(initialPackages, nonce));
        (bool deployed, address account) = LibClone.createDeterministicERC1967(msg.value, address(template), salt);
        Kernel k = Kernel(payable(account));
        if (deployed) {
            return k;
        }
        k.installModule(true, 0, initialPackages, hex"");
        return k;
    }

    function deployWithCall(Install[] calldata initialPackages, uint256 nonce, bytes calldata extraCall)
        external
        payable
        returns (Kernel)
    {
        bytes32 salt = keccak256(abi.encode(initialPackages, nonce));
        (bool deployed, address account) = LibClone.createDeterministicERC1967(msg.value, address(template), salt);
        Kernel k = Kernel(payable(account));
        if (!deployed) {
            k.installModule(true, 0, initialPackages, hex"");
        }
        (bool success,) = address(k).call(extraCall);
        require(success, "call failed");
        return k;
    }

    function getAddress(Install[] calldata initialPackages, uint256 nonce) public view virtual returns (address) {
        bytes32 salt = keccak256(abi.encode(initialPackages, nonce));
        return LibClone.predictDeterministicAddressERC1967(address(template), salt, address(this));
    }

    // Kernel UUPS ECDSA fallback
    function deployECDSA(address signer, Install[] calldata initialPackages, uint256 nonce) external payable returns (Kernel) {
        bytes32 salt = keccak256(abi.encode(initialPackages, nonce));
        (bool deployed, address account) = LibClone.createDeterministicERC1967(msg.value, address(template), salt);
        Kernel k = Kernel(payable(account));
        if (deployed) {
            return k;
        }
        k.installModule(true, 0, initialPackages, hex"");
        return k;
    }

    function deployECDSAWithCall(address signer, Install[] calldata initialPackages, uint256 nonce, bytes calldata extraCall)
        external
        payable
        returns (Kernel)
    {
        bytes32 salt = keccak256(abi.encode(initialPackages, nonce));
        (bool deployed, address account) = LibClone.createDeterministicERC1967(msg.value, address(template), salt);
        Kernel k = Kernel(payable(account));
        if (!deployed) {
            k.installModule(true, 0, initialPackages, hex"");
        }
        (bool success,) = address(k).call(extraCall);
        require(success, "call failed");
        return k;
    }

    function getECDSAAddress(address signer, Install[] calldata initialPackages, uint256 nonce) public view virtual returns (address) {
        bytes32 salt = keccak256(abi.encode(initialPackages, nonce));
        return LibClone.predictDeterministicAddressERC1967(address(template), salt, address(this));
    }
}
