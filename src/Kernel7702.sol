pragma solidity ^0.8.0;

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Kernel} from "./Kernel.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {Install} from "./types/Structs.sol";

contract Kernel7702 is Kernel {
    constructor(IEntryPoint _entryPoint) Kernel(_entryPoint) {}

    function initialize(Install[] calldata) external payable override {} // NO-OP

    function _verifyFallbackSignature(bytes32 hash, bytes calldata sig) internal view override returns (bool) {
        return ECDSA.tryRecoverCalldata(hash, sig) == address(this);
    }

    function _fallbackValidatorAvailable() internal pure override returns (bool) {
        return true;
    }

    function _erc1271RawAllowed() internal pure override returns (bool) {
        return true;
    }
}
