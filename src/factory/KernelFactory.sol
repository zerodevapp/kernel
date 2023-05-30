// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "openzeppelin-contracts/contracts/utils/Create2.sol";
import "./EIP1967Proxy.sol";
import "src/Kernel.sol";
import "src/validator/ECDSAValidator.sol";

import "./TempKernel.sol";

contract KernelFactory {
    TempKernel public immutable kernelTemplate;
    Kernel public immutable nextTemplate;
    IEntryPoint public immutable entryPoint;

    event AccountCreated(address indexed account, address indexed validator, bytes data, uint256 index);

    constructor(IEntryPoint _entryPoint) {
        kernelTemplate = new TempKernel(_entryPoint);
        nextTemplate = new Kernel(_entryPoint);
        entryPoint = _entryPoint;
    }

    function createAccount(IKernelValidator _validator, bytes calldata _data, uint256 _index)
        external
        returns (EIP1967Proxy proxy)
    {
        bytes32 salt = keccak256(abi.encodePacked(_validator, _data, _index));
        address addr = Create2.computeAddress(
            salt,
            keccak256(
                abi.encodePacked(
                    type(EIP1967Proxy).creationCode,
                    abi.encode(
                        address(kernelTemplate),
                        abi.encodeCall(TempKernel.initialize, (_validator, address(nextTemplate), _data))
                    )
                )
            )
        );
        if (addr.code.length > 0) {
            return EIP1967Proxy(payable(addr));
        }
        proxy =
        new EIP1967Proxy{salt: salt}(address(kernelTemplate), abi.encodeCall(TempKernel.initialize, (_validator, address(nextTemplate), _data)));
        emit AccountCreated(address(proxy), address(_validator), _data, _index);
    }

    function getAccountAddress(IKernelValidator _validator, bytes calldata _data, uint256 _index)
        public
        view
        returns (address)
    {
        bytes32 salt = keccak256(abi.encodePacked(_validator, _data, _index));
        return Create2.computeAddress(
            salt,
            keccak256(
                abi.encodePacked(
                    type(EIP1967Proxy).creationCode,
                    abi.encode(
                        address(kernelTemplate),
                        abi.encodeCall(TempKernel.initialize, (_validator, address(nextTemplate), _data))
                    )
                )
            )
        );
    }
}
