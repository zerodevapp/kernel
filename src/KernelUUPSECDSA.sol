pragma solidity ^0.8.0;

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Kernel} from "./Kernel.sol";
import {KernelUUPS} from "./KernelUUPS.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {LibClone} from "solady/utils/LibClone.sol";

contract KernelUUPSECDSA is KernelUUPS {
    constructor(IEntryPoint _entryPoint) KernelUUPS(_entryPoint) {}

    function _verifyFallbackSignature(bytes32 hash, bytes calldata sig) internal view override returns (bool) {
        address signer = address(uint160(bytes20(LibClone.argsOnERC1967(address(this), 0, 20))));

        return ECDSA.tryRecover(hash, sig) == signer;
    }
    
    function _initialized() internal override view returns(bool) {
        return true;
    }
}
