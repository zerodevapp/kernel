// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import "src/Kernel.sol";
import "src/validator/ECDSAValidator.sol";
// test artifacts
// test utils
import "forge-std/Test.sol";
import {ERC4337Utils} from "./utils/ERC4337Utils.sol";
import {KernelTestBase} from "./KernelTestBase.sol";

using ERC4337Utils for EntryPoint;
contract KernelECDSATest is KernelTestBase {
    function setUp() public {
        _initialize();
        defaultValidator = new ECDSAValidator();
        _setAddress();
    }

    function getInitializeData() internal override view returns(bytes memory) {
        return abi.encodeWithSelector(
            KernelStorage.initialize.selector,
            defaultValidator,
            abi.encodePacked(owner)
        );
    }

    function signUserOp(UserOperation memory op) internal override view returns(bytes memory) {
        return abi.encodePacked(bytes4(0x00000000), entryPoint.signUserOpHash(vm, ownerKey, op));
    }

    function signHash(bytes32 hash) internal override view returns(bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, ECDSA.toEthSignedMessageHash(hash));
        return abi.encodePacked(r, s, v);
    }
}
