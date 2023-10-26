// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {AdminLessERC1967Factory} from "./AdminLessERC1967Factory.sol";
import {IEntryPoint} from "I4337/interfaces/IEntryPoint.sol";
import {Ownable} from "solady/auth/Ownable.sol";

contract KernelFactory is AdminLessERC1967Factory, Ownable {
    IEntryPoint public entryPoint;
    mapping(address => bool) public isAllowedImplementation;

    constructor(address _owner, IEntryPoint _entryPoint) {
        _initializeOwner(_owner);
        entryPoint = _entryPoint;
    }

    function setImplementation(address _implementation, bool _allow) external onlyOwner {
        isAllowedImplementation[_implementation] = _allow;
    }

    function setEntryPoint(IEntryPoint _entryPoint) external onlyOwner {
        entryPoint = _entryPoint;
    }

    function createAccount(address _implementation, bytes calldata _data, uint256 _index)
        external
        payable
        returns (address proxy)
    {
        require(isAllowedImplementation[_implementation], "KernelFactory: implementation not allowed");
        bytes32 salt = bytes32(uint256(keccak256(abi.encodePacked(_data, _index))) & type(uint96).max);
        proxy = deployDeterministicAndCall(_implementation, salt, _data);
    }

    function getAccountAddress(bytes calldata _data, uint256 _index) public view returns (address) {
        bytes32 salt = bytes32(uint256(keccak256(abi.encodePacked(_data, _index))) & type(uint96).max);
        return predictDeterministicAddress(salt);
    }

    // stake functions
    function addStake(uint32 unstakeDelaySec) external payable onlyOwner {
        entryPoint.addStake{value: msg.value}(unstakeDelaySec);
    }

    function unlockStake() external onlyOwner {
        entryPoint.unlockStake();
    }

    function withdrawStake(address payable withdrawAddress) external onlyOwner {
        entryPoint.withdrawStake(withdrawAddress);
    }
}
