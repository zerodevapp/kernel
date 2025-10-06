pragma solidity ^0.8.0;

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Kernel} from "./Kernel.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";

contract Kernel7702 is Kernel {
    constructor(IEntryPoint _entryPoint) Kernel(_entryPoint) {}

    function _verifyFallbackSignature(bytes32 hash, bytes calldata sig) internal view override returns (bool) {
        return ECDSA.tryRecover(hash, sig) == address(this);
    }

    function _statelessInitializeCheck() internal view override returns (bool) {
        return true;
    }

    function _fallbackValidatorAvailable() internal pure override returns (bool) {
        return true;
    }
}
