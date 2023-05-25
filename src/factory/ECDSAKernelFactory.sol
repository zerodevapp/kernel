// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import "./KernelFactory.sol";
import "src/validator/ECDSAValidator.sol";

contract ECDSAKernelFactory {
    KernelFactory immutable public singletonFactory;
    ECDSAValidator immutable public validator;
    IEntryPoint immutable public entryPoint;

    address public staker;

    constructor(KernelFactory _singletonFactory, ECDSAValidator _validator, IEntryPoint _entryPoint) {
        singletonFactory = _singletonFactory;
        validator = _validator;
        entryPoint = _entryPoint;
        staker = msg.sender;
    }

    function setStaker(address _staker) external {
        require(msg.sender == staker, "ECDSAKernelFactory: forbidden");
        staker = _staker;
    }

    function addStake(uint32 _delay) external payable {
        require(msg.sender == staker, "ECDSAKernelFactory: forbidden");
        entryPoint.addStake{value: msg.value}(_delay);
    }

    function unlockStake() external {
        require(msg.sender == staker, "ECDSAKernelFactory: forbidden");
        entryPoint.unlockStake();
    }

    function withdrawStake(address payable _to) external {
        require(msg.sender == staker, "ECDSAKernelFactory: forbidden");
        entryPoint.withdrawStake(_to);
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
