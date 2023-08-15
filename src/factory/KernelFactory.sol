// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./AdminLessERC1967Factory.sol";

import "openzeppelin-contracts/contracts/utils/Create2.sol";
import "src/Kernel.sol";
import "src/validator/ECDSAValidator.sol";
import "solady/auth/Ownable.sol";
import "src/utils/Create2Flag.sol";

contract KernelFactory is AdminLessERC1967Factory, Ownable {
    error InvalidImplementation();

    constructor(address _owner) {
        _initializeOwner(_owner);
    }

    function setImplementation(address _implementation) external onlyOwner {
        Create2Flag.on(bytes32(bytes20(_implementation)));
    }

    function isAllowedImplementation(address _implementation) external view returns (bool) {
        return !Create2Flag.isOff(bytes32(bytes20(_implementation)));
    }

    function createAccount(address _implementation, bytes calldata _data, uint256 _index)
        external
        payable
        returns (address proxy)
    {
        if (Create2Flag.isOff(bytes32(bytes20(_implementation)))) {
            revert InvalidImplementation();
        }
        bytes32 salt = bytes32(uint256(keccak256(abi.encodePacked(_data, _index))) & type(uint96).max);
        proxy = deployDeterministicAndCall(_implementation, salt, _data);
    }

    function getAccountAddress(bytes calldata _data, uint256 _index) public view returns (address) {
        bytes32 salt = bytes32(uint256(keccak256(abi.encodePacked(_data, _index))) & type(uint96).max);
        return predictDeterministicAddress(salt);
    }
}
