// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IEntryPoint} from "I4337/interfaces/IEntryPoint.sol";
import "src/Kernel.sol";
import "src/validator/ECDSAValidator.sol";
// test artifacts
// test utils
import "forge-std/Test.sol";
import {ERC4337Utils} from "./utils/ERC4337Utils.sol";
import {KernelTestBase} from "./KernelTestBase.sol";
import {TestExecutor} from "./mock/TestExecutor.sol";
import {TestValidator} from "./mock/TestValidator.sol";
import {IKernel} from "src/interfaces/IKernel.sol";

using ERC4337Utils for IEntryPoint;

contract KernelECDSATest is KernelTestBase {
    function setUp() public virtual {
        _initialize();
        defaultValidator = new ECDSAValidator();
        _setAddress();
        _setExecutionDetail();
    }

    function test_ignore() external {}

    function _setExecutionDetail() internal virtual override {
        executionDetail.executor = address(new TestExecutor());
        executionSig = TestExecutor.doNothing.selector;
        executionDetail.validator = new TestValidator();
    }

    function getEnableData() internal view virtual override returns (bytes memory) {
        return "";
    }

    function getValidatorSignature(UserOperation memory) internal view virtual override returns (bytes memory) {
        return "";
    }

    function getOwners() internal view override returns (address[] memory) {
        address[] memory owners = new address[](1);
        owners[0] = owner;
        return owners;
    }

    function getInitializeData() internal view override returns (bytes memory) {
        return abi.encodeWithSelector(KernelStorage.initialize.selector, defaultValidator, abi.encodePacked(owner));
    }

    function signUserOp(UserOperation memory op) internal view override returns (bytes memory) {
        return abi.encodePacked(bytes4(0x00000000), entryPoint.signUserOpHash(vm, ownerKey, op));
    }

    function getWrongSignature(UserOperation memory op) internal view override returns (bytes memory) {
        return abi.encodePacked(bytes4(0x00000000), entryPoint.signUserOpHash(vm, ownerKey + 1, op));
    }

    function signHash(bytes32 hash) internal view override returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, ECDSA.toEthSignedMessageHash(hash));
        return abi.encodePacked(r, s, v);
    }

    function getWrongSignature(bytes32 hash) internal view override returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey + 1, ECDSA.toEthSignedMessageHash(hash));
        return abi.encodePacked(r, s, v);
    }

    function test_default_validator_enable() external override {
        UserOperation memory op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(
                IKernel.execute.selector,
                address(defaultValidator),
                0,
                abi.encodeWithSelector(ECDSAValidator.enable.selector, abi.encodePacked(address(0xdeadbeef))),
                Operation.Call
            )
        );
        op.signature = signUserOp(op);
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);
        (address owner) = ECDSAValidator(address(defaultValidator)).ecdsaValidatorStorage(address(kernel));
        assertEq(owner, address(0xdeadbeef), "owner should be 0xdeadbeef");
    }

    function test_default_validator_disable() external override {
        UserOperation memory op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(
                IKernel.execute.selector,
                address(defaultValidator),
                0,
                abi.encodeWithSelector(ECDSAValidator.disable.selector, ""),
                Operation.Call
            )
        );
        op.signature = signUserOp(op);
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);
        (address owner) = ECDSAValidator(address(defaultValidator)).ecdsaValidatorStorage(address(kernel));
        assertEq(owner, address(0), "owner should be 0");
    }
}
