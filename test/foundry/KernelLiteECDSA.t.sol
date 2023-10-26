// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IEntryPoint} from "I4337/interfaces/IEntryPoint.sol";
import "src/Kernel.sol";
import "src/lite/KernelLiteECDSA.sol";
// test artifacts
// test utils
import "forge-std/Test.sol";
import {ERC4337Utils} from "./utils/ERC4337Utils.sol";
import {KernelTestBase} from "./KernelTestBase.sol";
import {TestExecutor} from "./mock/TestExecutor.sol";
import {TestValidator} from "./mock/TestValidator.sol";
import {ECDSAValidator} from "src/validator/ECDSAValidator.sol";

using ERC4337Utils for IEntryPoint;

contract KernelECDSATest is KernelTestBase {
    ECDSAValidator ecdsa;

    function setUp() public {
        ecdsa = new ECDSAValidator();
        _initialize();
        kernelImpl = Kernel(payable(address(new KernelLiteECDSA(entryPoint, ecdsa))));
        vm.startPrank(factoryOwner);
        factory.setImplementation(address(kernelImpl), true);
        vm.stopPrank();

        _setAddress();
        _setExecutionDetail();
    }

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
        return abi.encodeWithSelector(KernelStorage.initialize.selector, address(ecdsa), abi.encodePacked(owner));
    }

    function test_set_default_validator() external override {
        TestValidator newValidator = new TestValidator();
        bytes memory empty;
        UserOperation memory op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(KernelStorage.setDefaultValidator.selector, address(newValidator), empty)
        );
        op.signature = signUserOp(op);
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        vm.expectEmit(true, true, true, false, address(entryPoint));
        emit UserOperationEvent(entryPoint.getUserOpHash(op), address(kernel), address(0), op.nonce, false, 0, 0);
        entryPoint.handleOps(ops, beneficiary);
    }

    function signUserOp(UserOperation memory op) internal view override returns (bytes memory) {
        return abi.encodePacked(bytes4(0x00000000), entryPoint.signUserOpHash(vm, ownerKey, op));
    }

    function signHash(bytes32 hash) internal view override returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, ECDSA.toEthSignedMessageHash(hash));
        return abi.encodePacked(r, s, v);
    }

    function getWrongSignature(UserOperation memory op) internal view override returns (bytes memory) {
        return abi.encodePacked(bytes4(0x00000000), entryPoint.signUserOpHash(vm, ownerKey + 1, op));
    }

    function getWrongSignature(bytes32 hash) internal view override returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey + 1, ECDSA.toEthSignedMessageHash(hash));
        return abi.encodePacked(r, s, v);
    }

    function test_default_validator_enable() external override {
        vm.skip(true);
    }

    function test_default_validator_disable() external override {
        vm.skip(true);
    }

    function test_fail_validate_not_activate() external override {
        vm.skip(true);
    }

    function test_transfer_ownership() external {
        address newOwner = makeAddr("new owner");
        UserOperation memory op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(KernelLiteECDSA.transferOwnership.selector, newOwner)
        );
        op.signature = signUserOp(op);
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        vm.expectEmit(true, true, true, false, address(entryPoint));
        emit UserOperationEvent(entryPoint.getUserOpHash(op), address(kernel), address(0), op.nonce, false, 0, 0);
        entryPoint.handleOps(ops, beneficiary);
    }
}
