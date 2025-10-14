pragma solidity ^0.8.0;

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {KernelUUPS} from "./KernelUUPS.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {LibClone} from "solady/utils/LibClone.sol";
import {Install} from "./core/ModuleManager.sol";

contract KernelImmutableECDSA is KernelUUPS {
    constructor(IEntryPoint _entryPoint) KernelUUPS(_entryPoint) {}

    function _verifyFallbackSignature(bytes32 hash, bytes calldata sig) internal view override returns (bool) {
        address signer = address(uint160(bytes20(LibClone.argsOnERC1967(address(this), 0, 20))));

        if (ECDSA.tryRecover(hash, sig) == signer) {
            return true;
        }
        if (ECDSA.tryRecover(ECDSA.toEthSignedMessageHash(hash), sig) == signer) {
            return true;
        }
        return false;
    }

    function _statelessInitializeCheck() internal view override returns (bool) {
        return false;
    }

    function _fallbackValidatorAvailable() internal pure override returns (bool) {
        return true;
    }

    function _initialize(Install[] calldata packages) internal override {
        _install(packages);
    }
}
