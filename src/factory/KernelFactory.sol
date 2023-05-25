// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "openzeppelin-contracts/contracts/utils/Create2.sol";
import "./EIP1967Proxy.sol";
import "src/Kernel.sol";
import "src/validator/ECDSAValidator.sol";

contract KernelFactory {
    Kernel public immutable kernelTemplate;
    IEntryPoint public immutable entryPoint;

    address public staker;

    event AccountCreated(address indexed account, address indexed validator, bytes data, uint256 index);

    constructor(IEntryPoint _entryPoint) {
        kernelTemplate = new Kernel(_entryPoint);
        entryPoint = _entryPoint;
        staker = msg.sender;
    }

    function setStaker(address _staker) external {
        require(msg.sender == staker, "KernelFactory: forbidden");
        staker = _staker;
    }

    function addStake(uint32 _delay) external payable {
        require(msg.sender == staker, "KernelFactory: forbidden");
        entryPoint.addStake{value: msg.value}(_delay);
    }

    function unlockStake() external {
        require(msg.sender == staker, "KernelFactory: forbidden");
        entryPoint.unlockStake();
    }

    function withdrawStake(address payable _to) external {
        require(msg.sender == staker, "KernelFactory: forbidden");
        entryPoint.withdrawStake(_to);
    }

    function createAccount(IKernelValidator _validator, bytes calldata _data, uint256 _index) external returns (EIP1967Proxy proxy) {
        bytes32 salt = keccak256(abi.encodePacked(_validator, _data, _index));
        address addr = Create2.computeAddress(
            salt,
            keccak256(
                abi.encodePacked(
                    type(EIP1967Proxy).creationCode,
                    abi.encode(address(kernelTemplate), abi.encodeCall(KernelStorage.initialize, (_validator, _data)))
                )
            )
        );
        if (addr.code.length > 0) {
            return EIP1967Proxy(payable(addr));
        }
        proxy =
        new EIP1967Proxy{salt: salt}(address(kernelTemplate), abi.encodeWithSelector(KernelStorage.initialize.selector, _validator, _data));
        emit AccountCreated(address(proxy), address(_validator), _data, _index);
    }

    function getAccountAddress(IKernelValidator _validator, bytes calldata _data, uint256 _index) public view returns (address) {
        bytes32 salt = keccak256(abi.encodePacked(_validator, _data, _index));
        return Create2.computeAddress(
            salt,
            keccak256(
                abi.encodePacked(
                    type(EIP1967Proxy).creationCode,
                    abi.encode(address(kernelTemplate), abi.encodeCall(KernelStorage.initialize, (_validator, _data))
                )
            )
        ));
    }
}
