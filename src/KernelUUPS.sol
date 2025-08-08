pragma solidity ^0.8.0;

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Kernel} from "./Kernel.sol";
import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";
import {Initializable} from "solady/utils/Initializable.sol";

contract KernelUUPS is Kernel, UUPSUpgradeable, Initializable {
    constructor(IEntryPoint _entryPoint) Kernel(_entryPoint) {}

    function _authorizeUpgrade(address) internal override {
        _onlyEntryPointOrSelf();
    }
}
