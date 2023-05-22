// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "openzeppelin-contracts/contracts/utils/Create2.sol";
import "./EIP1967Proxy.sol";
import "src/Kernel.sol";
import "src/validator/ECDSAValidator.sol";

contract KernelFactory {
    Kernel public immutable kernelTemplate;

    event AccountCreated(address indexed account, address indexed owner, uint256 index);

    constructor(IEntryPoint _entryPoint) {
        kernelTemplate = new Kernel(_entryPoint);
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