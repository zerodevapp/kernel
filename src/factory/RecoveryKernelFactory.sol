// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import "./KernelFactory.sol";
import "src/validator/RecoveryPlugin.sol";

contract RecoveryKernelFactory {
    KernelFactory public immutable singletonFactory;
    RecoveryPlugin public immutable validator;
    IEntryPoint public immutable entryPoint;

    constructor(KernelFactory _singletonFactory, RecoveryPlugin _validator, IEntryPoint _entryPoint) {
        singletonFactory = _singletonFactory;
        validator = _validator;
        entryPoint = _entryPoint;
    }

    function createAccount(bytes memory data, uint256 _index) external returns (EIP1967Proxy proxy) {
        proxy = singletonFactory.createAccount(validator, data, _index);
    }

    function getAccountAddress(bytes memory data, uint256 _index) public view returns (address) {
        return singletonFactory.getAccountAddress(validator, data, _index);
    }
}