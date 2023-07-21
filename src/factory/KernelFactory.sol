// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./AdminLessERC1967Factory.sol";

import "openzeppelin-contracts/contracts/utils/Create2.sol";
import "src/Kernel.sol";
import "src/validator/ECDSAValidator.sol";

contract KernelFactory {
    AdminLessERC1967Factory public immutable erc1967factory;
    Kernel public immutable kernelTemplate;
    IEntryPoint public immutable entryPoint;

    event AccountCreated(address indexed account, address indexed validator, bytes data, uint256 index);

    constructor(AdminLessERC1967Factory _erc1967factory, IEntryPoint _entryPoint) {
        erc1967factory = _erc1967factory;
        entryPoint = _entryPoint;
        kernelTemplate = new Kernel(_entryPoint);
    }

    function createAccount(IKernelValidator _validator, bytes calldata _data, uint256 _index)
        external
        payable
        returns (address proxy)
    {
        bytes memory initData = abi.encodeWithSelector(KernelStorage.initialize.selector, _validator, _data);
        bytes32 salt = bytes32(uint256(keccak256(abi.encodePacked(_validator, _data, _index))) & type(uint96).max);
        proxy = erc1967factory.deployDeterministicAndCall(address(kernelTemplate), salt, initData);
    }

    function getAccountAddress(IKernelValidator _validator, bytes calldata _data, uint256 _index)
        public
        view
        returns (address)
    {
        bytes32 salt = bytes32(uint256(keccak256(abi.encodePacked(_validator, _data, _index))) & type(uint96).max);
        return erc1967factory.predictDeterministicAddress(salt);
    }
}
