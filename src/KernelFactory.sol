pragma solidity ^0.8.0;

import {Kernel, Install} from "./Kernel.sol";
import {LibClone} from "solady/utils/LibClone.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

contract KernelFactory {
    Kernel public immutable template;

    constructor(IEntryPoint _entryPoint) {
        template = new Kernel(_entryPoint);
    }

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

    //    function deployWithAdditionalPackage(
    //        Install[] calldata initialPackages,
    //        uint256 nonce,
    //        bool replayable,
    //        uint256 packageNonce,
    //        Install[] calldata packages,
    //        bytes calldata signature
    //    ) external payable returns (Kernel) {
    //        bytes32 salt = keccak256(abi.encode(initialPackages, nonce));
    //        (bool deployed, address account) = LibClone.createDeterministicERC1967(msg.value, address(template), salt);
    //        Kernel k = Kernel(payable(account));
    //        if(!deployed) {
    //            k.installModule(true, 0, initialPackages, hex"");
    //        }
    //        k.installModule(replayable, packageNonce, packages, signature);
    //        return k;
    //    }
}
