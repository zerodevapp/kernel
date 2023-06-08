// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import "./KernelFactory.sol";
import "src/validator/ECDSAValidator.sol";

contract ECDSAKernelFactory {
    KernelFactory public immutable singletonFactory;
    ECDSAValidator public immutable validator;
    IEntryPoint public immutable entryPoint;

    constructor(KernelFactory _singletonFactory, ECDSAValidator _validator, IEntryPoint _entryPoint) {
        singletonFactory = _singletonFactory;
        validator = _validator;
        entryPoint = _entryPoint;
    }

    function createAccount(address _owner, uint256 _index) external returns (EIP1967Proxy proxy) {
        bytes memory data = abi.encodePacked(_owner);
        proxy = singletonFactory.createAccount(validator, data, _index);
    }

    function getAccountAddress(address _owner, uint256 _index) public view returns (address) {
        bytes memory data = abi.encodePacked(_owner);
        return singletonFactory.getAccountAddress(validator, data, _index);
    }
}
