// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import "src/factory/AdminLessERC1967Factory.sol";
import "src/factory/KernelFactory.sol";
import "src/Kernel.sol";
import "src/validator/ECDSAValidator.sol";
// test artifacts
import "src/test/TestValidator.sol";
import "src/test/TestERC721.sol";
import "src/test/TestKernel.sol";
// test utils
import "forge-std/Test.sol";
import {ERC4337Utils, KernelTestBase} from "./utils/ERC4337Utils.sol";

using ERC4337Utils for EntryPoint;

contract KernelTest is KernelTestBase {
    function setUp() public {
        _initialize();
        defaultValidator = new ECDSAValidator();
        _setAddress();
    }

    function test_should_return_address_if_deployed() external {
        address proxy = factory.createAccount(
            address(kernelImpl),
            abi.encodeWithSelector(
                KernelStorage.initialize.selector, defaultValidator, abi.encodePacked(owner)
            ),
            0
        );
        assertEq(proxy, address(kernel));
    }

    function test_initialize_twice() external {
        vm.expectRevert();
        kernel.initialize(defaultValidator, abi.encodePacked(owner));
    }

    function test_external_call_default() external {
        vm.startPrank(owner);
        (bool success,) = address(kernel).call(abi.encodePacked("Hello world"));
        assertEq(success, true);
    }

    function test_validate_signature() external {
        Kernel kernel2 = Kernel(
            payable(
                address(
                    factory.createAccount(
                        address(kernelImpl),
                        abi.encodeWithSelector(
                            KernelStorage.initialize.selector, defaultValidator, abi.encodePacked(owner)
                        ),
                        1
                    )
                )
            )
        );
        bytes32 hash = keccak256(abi.encodePacked("hello world"));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        assertEq(kernel2.isValidSignature(hash, abi.encodePacked(r, s, v)), Kernel.isValidSignature.selector);
    }

    function test_validate_userOp() external {
        TestKernel kernel2 = new TestKernel(entryPoint);
        kernel2.sudoInitialize(defaultValidator, abi.encodePacked(owner));

        UserOperation memory op = entryPoint.fillUserOp(
            address(kernel), abi.encodeWithSelector(Kernel.execute.selector, address(0), 0, bytes(""))
        );
        op.signature = abi.encodePacked(bytes4(0x00000000), entryPoint.signUserOpHash(vm, ownerKey, op));
        bytes32 hash = entryPoint.getUserOpHash(op);
        vm.startPrank(address(entryPoint));
        kernel2.validateUserOp(op, hash, 0);
        vm.stopPrank();
    }

    function test_set_default_validator() external {
        TestValidator newValidator = new TestValidator();
        bytes memory empty;
        UserOperation memory op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(KernelStorage.setDefaultValidator.selector, address(newValidator), empty)
        );
        op.signature = abi.encodePacked(bytes4(0x00000000), entryPoint.signUserOpHash(vm, ownerKey, op));
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);
        assertEq(address(KernelStorage(address(kernel)).getDefaultValidator()), address(newValidator));
    }

    function test_disable_mode() external {
        vm.warp(1000);
        bytes memory empty;
        UserOperation memory op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(KernelStorage.disableMode.selector, bytes4(0x00000001), address(0), empty)
        );
        op.signature = abi.encodePacked(bytes4(0x00000000), entryPoint.signUserOpHash(vm, ownerKey, op));
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);
        assertEq(uint256(bytes32(KernelStorage(address(kernel)).getDisabledMode())), 1 << 224);
    }

    function test_set_execution() external {
        console.log("owner", owner);
        TestValidator newValidator = new TestValidator();
        UserOperation memory op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(
                KernelStorage.setExecution.selector,
                bytes4(0xdeadbeef),
                address(0xdead),
                address(newValidator),
                uint48(0),
                uint48(0),
                bytes("")
            )
        );
        op.signature = abi.encodePacked(bytes4(0x00000000), entryPoint.signUserOpHash(vm, ownerKey, op));
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);
        ExecutionDetail memory execution = KernelStorage(address(kernel)).getExecution(bytes4(0xdeadbeef));
        assertEq(execution.executor, address(0xdead));
        assertEq(address(execution.validator), address(newValidator));
        assertEq(uint256(ValidUntil.unwrap(execution.validUntil)), uint256(0));
        assertEq(uint256(ValidAfter.unwrap(execution.validAfter)), uint256(0));
    }

    function test_external_call_execution() external {
        console.log("owner", owner);
        TestValidator newValidator = new TestValidator();
        UserOperation memory op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(
                KernelStorage.setExecution.selector,
                bytes4(0xdeadbeef),
                address(0xdead),
                address(newValidator),
                uint48(0),
                uint48(0),
                bytes("")
            )
        );
        op.signature = abi.encodePacked(bytes4(0x00000000), entryPoint.signUserOpHash(vm, ownerKey, op));
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);
        ExecutionDetail memory execution = KernelStorage(address(kernel)).getExecution(bytes4(0xdeadbeef));
        assertEq(execution.executor, address(0xdead));
        assertEq(address(execution.validator), address(newValidator));
        assertEq(uint256(ValidUntil.unwrap(execution.validUntil)), uint256(0));
        assertEq(uint256(ValidAfter.unwrap(execution.validAfter)), uint256(0));

        address randomAddr = makeAddr("random");
        newValidator.sudoSetCaller(address(kernel), randomAddr);
        vm.startPrank(randomAddr);
        (bool success,) = address(kernel).call(abi.encodePacked(bytes4(0xdeadbeef)));
        assertEq(success, true);
        vm.stopPrank();

        address notAllowed = makeAddr("notAllowed");
        vm.startPrank(notAllowed);
        (bool success2,) = address(kernel).call(abi.encodePacked(bytes4(0xdeadbeef)));
        assertEq(success2, false);
        vm.stopPrank();
    }
}
