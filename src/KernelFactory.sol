pragma solidity ^0.8.0;

import {Kernel, Install} from "./Kernel.sol";
import {KernelUUPS} from "./KernelUUPS.sol";
import {KernelImmutableECDSA} from "./KernelImmutableECDSA.sol";
import {LibClone} from "solady/utils/LibClone.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

contract KernelFactory {
    KernelUUPS public immutable uups;
    KernelImmutableECDSA public immutable immutableECDSA;

    constructor(KernelUUPS _uups, KernelImmutableECDSA _immutableECDSA) {
        uups = _uups;
        immutableECDSA = _immutableECDSA;
    }

    function checkInitialized(address account, bytes calldata initData) external view returns (bool) {
        bytes4 selector = bytes4(initData[0:4]);
        ( /*replayable*/ , /*nonce*/, Install[] memory packages, /*sig*/ ) =
            abi.decode(initData, (bool, uint256, Install[], bytes));

        // naively check if the package has been installed by only checking the nonce
        for (uint256 i = 0; i < packages.length; i++) {
            Install memory p = packages[i];
            uint256 n = p.nonce;
            uint192 key = uint192(p.nonce >> 8);
            uint64 seq = uint64(p.nonce);

            if (Kernel(account).nonce(key) <= seq) {
                return false;
            }
        }
        return true;
    }

    // Kernel UUPS
    function deploy(Install[] calldata initialPackages, uint256 nonce) external payable returns (Kernel) {
        bytes32 salt = keccak256(abi.encode(initialPackages, nonce));
        (bool deployed, address account) = LibClone.createDeterministicERC1967(msg.value, address(uups), salt);
        Kernel k = Kernel(payable(account));
        if (deployed) {
            return k;
        }
        k.initialize(initialPackages);
        return k;
    }

    function deployWithCall(Install[] calldata initialPackages, uint256 nonce, bytes calldata extraCall)
        external
        payable
        returns (Kernel)
    {
        bytes32 salt = keccak256(abi.encode(initialPackages, nonce));
        (bool deployed, address account) = LibClone.createDeterministicERC1967(msg.value, address(uups), salt);
        Kernel k = Kernel(payable(account));
        if (!deployed) {
            k.initialize(initialPackages);
        }
        (bool success,) = address(k).call(extraCall);
        require(success, "call failed");
        return k;
    }

    function getAddress(Install[] calldata initialPackages, uint256 nonce) public view virtual returns (address) {
        bytes32 salt = keccak256(abi.encode(initialPackages, nonce));
        return LibClone.predictDeterministicAddressERC1967(address(uups), salt, address(this));
    }

    // Kernel UUPS ECDSA fallback
    function deployECDSA(address signer, Install[] calldata initialPackages, uint256 nonce)
        external
        payable
        returns (Kernel)
    {
        bytes32 salt = keccak256(abi.encode(initialPackages, nonce));
        (, address account) =
            LibClone.createDeterministicERC1967(address(immutableECDSA), abi.encodePacked(signer), salt);
        Kernel k = Kernel(payable(account));
        k.initialize(initialPackages);
        return k;
    }

    function deployECDSAWithCall(
        address signer,
        Install[] calldata initialPackages,
        uint256 nonce,
        bytes calldata extraCall
    ) external payable returns (Kernel) {
        bytes32 salt = keccak256(abi.encode(initialPackages, nonce));
        (, address account) =
            LibClone.createDeterministicERC1967(address(immutableECDSA), abi.encodePacked(signer), salt);
        Kernel k = Kernel(payable(account));
        k.initialize(initialPackages);
        (bool success,) = address(k).call(extraCall);
        require(success, "call failed");
        return k;
    }

    function getECDSAAddress(address signer, Install[] calldata initialPackages, uint256 nonce)
        public
        view
        virtual
        returns (address)
    {
        bytes32 salt = keccak256(abi.encode(initialPackages, nonce));
        return LibClone.predictDeterministicAddressERC1967(
            address(immutableECDSA), abi.encodePacked(signer), salt, address(this)
        );
    }
}
