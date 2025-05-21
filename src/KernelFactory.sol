pragma solidity ^0.8.0;

import {Kernel, Install} from "./Kernel.sol";
import {LibClone} from "solady/utils/LibClone.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

contract KernelFactory {
    Kernel public immutable template;

    constructor(IEntryPoint _entryPoint) {
        template = new Kernel(_entryPoint);
    }

    function deploy(bytes calldata initData) external payable returns (Kernel) {
        bytes32 salt = keccak256(initData);
        (bool deployed, address account) = LibClone.createDeterministicERC1967(msg.value, address(template), salt);
        return Kernel(payable(account));
    }

    function deployWithAdditionalPackage(bytes calldata initData, bool replayable, Install[] calldata packages, bytes calldata signature) external payable returns (Kernel) {
        bytes32 salt = keccak256(initData);
        (bool deployed, address account) = LibClone.createDeterministicERC1967(msg.value, address(template), salt);

        Kernel k = Kernel(payable(account));
        k.installModule(replayable, packages, signature);
        return k;
    }
}
