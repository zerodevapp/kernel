// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import "src/Kernel.sol";
import "src/lite/KernelLiteECDSA.sol";
// test artifacts
// test utils
import "forge-std/Test.sol";
import {ERC4337Utils} from "./utils/ERC4337Utils.sol";
import {KernelTestBase} from "./KernelTestBase.sol";

using ERC4337Utils for EntryPoint;

contract KernelECDSATest is KernelTestBase {
    function setUp() public {
        _initialize();
        kernelImpl = Kernel(payable(address(new KernelLiteECDSA(entryPoint))));
        vm.startPrank(factoryOwner);
        factory.setImplementation(address(kernelImpl), true);
        vm.stopPrank();

        _setAddress();
    }

    function getInitializeData() internal view override returns (bytes memory) {
        return abi.encodeWithSelector(KernelStorage.initialize.selector, defaultValidator, abi.encodePacked(owner));
    }

    function test_set_default_validator() external override {
        vm.skip(true);
    }

    function signUserOp(UserOperation memory op) internal view override returns (bytes memory) {
        return abi.encodePacked(bytes4(0x00000000), entryPoint.signUserOpHash(vm, ownerKey, op));
    }

    function signHash(bytes32 hash) internal view override returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, ECDSA.toEthSignedMessageHash(hash));
        return abi.encodePacked(r, s, v);
    }
}
