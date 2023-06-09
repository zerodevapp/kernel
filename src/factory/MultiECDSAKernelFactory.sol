// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import "./KernelFactory.sol";
import "src/validator/MultiECDSAValidator.sol";
import "src/interfaces/IAddressBook.sol";

contract MultiECDSAKernelFactory is IAddressBook {
    KernelFactory public immutable singletonFactory;
    MultiECDSAValidator public immutable validator;
    IEntryPoint public immutable entryPoint;

    address[] public owners;

    constructor(KernelFactory _singletonFactory, MultiECDSAValidator _validator, IEntryPoint _entryPoint) {
        singletonFactory = _singletonFactory;
        validator = _validator;
        entryPoint = _entryPoint;
    }

    // TODO: add onlyOwner
    function setOwners(address[] calldata _owners) external {
        owners = _owners;
    }

    function getOwners() external view override returns(address[] memory) {
        return owners;
    }

    function createAccount(uint256 _index) external returns (EIP1967Proxy proxy) {
        bytes memory data = abi.encodePacked(address(this));
        proxy = singletonFactory.createAccount(validator, data, _index);
    }

    function getAccountAddress(uint256 _index) public view returns (address) {
        bytes memory data = abi.encodePacked(address(this));
        return singletonFactory.getAccountAddress(validator, data, _index);
    }
}
