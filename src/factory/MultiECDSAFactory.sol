pragma solidity ^0.8.0;

import "./KernelFactory.sol";
import "src/interfaces/IAddressBook.sol";

contract MultiECDSAFactory is KernelFactory, IAddressBook {
    address[] owners;
    address public implementation;

    constructor(
        address _owner,
        IEntryPoint _entryPoint,
        address _implementation
    ) KernelFactory(_owner, _entryPoint) {
        implementation = _implementation;
    }

    function getOwners() external view override returns (address[] memory) {
        return owners;
    }

    function setOwners(address[] memory _owners) external onlyOwner {
        owners = _owners;
    }
}
