// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "src/factory/KernelFactory.sol";
import "src/factory/RecoveryKernelFactory.sol";
import "src/Kernel.sol";
import "src/validator/RecoveryPlugin.sol";
import "src/factory/EIP1967Proxy.sol";
// test artifacts
import "src/test/TestValidator.sol";
import "src/test/TestERC721.sol";
// test utils
import "forge-std/Test.sol";
import {ERC4337Utils} from "./ERC4337Utils.sol";

using ERC4337Utils for EntryPoint;

contract RecoveryTest is Test{
    Kernel kernel;
    KernelFactory factory;
    RecoveryKernelFactory recoveryFactory;
    EntryPoint entryPoint;
    RecoveryPlugin validator;
    address owner;
    uint256 ownerKey;
    address payable beneficiary;

    function setUp() public {
        (owner, ownerKey) = makeAddrAndKey("owner");
        entryPoint = new EntryPoint();
        factory = new KernelFactory(entryPoint);

        validator = new RecoveryPlugin();
        recoveryFactory = new RecoveryKernelFactory(factory, validator, entryPoint);

        kernel = Kernel(payable(recoveryFactory.createAccount(owner, 0)));
        vm.deal(address(kernel), 1e30);
        beneficiary = payable(address(makeAddr("beneficiary")));
    }

    function test_initialize_twice() external {
        vm.expectRevert();
        kernel.initialize(validator, abi.encodePacked(owner));
    }

    function test_initialize() public {
        Kernel newKernel = Kernel(
            payable(
                address(
                    new EIP1967Proxy(
                    address(factory.nextTemplate()),
                    abi.encodeWithSelector(
                    KernelStorage.initialize.selector,
                    validator,
                    abi.encodePacked(owner)
                    )
                    )
                )
            )
        );
        RecoveryPluginStorage memory storage_ =
            RecoveryPluginStorage(validator.recoveryPluginStorage(address(newKernel)));
        assertEq(storage_.owner, owner);
    }
}