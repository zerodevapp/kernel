// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "src/factory/KernelFactory.sol";
import "src/validator/ECDSAValidator.sol";
import "src/Kernel.sol";
import "src/validator/KillSwitchValidator.sol";
import "src/executor/KillSwitchAction.sol";
// test utils
import "forge-std/Test.sol";
import "../utils/ERC4337Utils.sol";
import {KernelTestBase} from "../KernelTestBase.sol";
import {KernelECDSATest} from "../KernelECDSA.t.sol";

using ERC4337Utils for EntryPoint;

contract KillSwitchValidatorTest is KernelECDSATest {
    KillSwitchValidator killSwitch;
    KillSwitchAction action;
    address guardian;
    uint256 guardianKey;

    function setUp() public override {
        super.setUp();
        (guardian, guardianKey) = makeAddrAndKey("guardian");
        killSwitch = new KillSwitchValidator();
        action = new KillSwitchAction(killSwitch);
    }

    function test_force_unblock() external {
        UserOperation memory op = entryPoint.fillUserOp(
            address(kernel), abi.encodeWithSelector(Kernel.execute.selector, owner, 0, "", Operation.Call)
        );

        op.signature = bytes.concat(bytes4(0), entryPoint.signUserOpHash(vm, ownerKey, op));
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);

        op = entryPoint.fillUserOp(address(kernel), abi.encodeWithSelector(KillSwitchAction.toggleKillSwitch.selector));
        address guardianKeyAddr;
        uint256 guardianKeyPriv;
        (guardianKeyAddr, guardianKeyPriv) = makeAddrAndKey("guardianKey");
        bytes memory enableData = abi.encodePacked(guardianKeyAddr);
        {
            bytes32 digest = getTypedDataHash(
                address(kernel),
                KillSwitchAction.toggleKillSwitch.selector,
                0,
                0,
                address(killSwitch),
                address(action),
                enableData
            );
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);

            op.signature = abi.encodePacked(
                bytes4(0x00000002),
                uint48(0),
                uint48(0),
                address(killSwitch),
                address(action),
                uint256(enableData.length),
                enableData,
                uint256(65),
                r,
                s,
                v
            );
        }

        uint256 pausedUntil = block.timestamp + 1000;

        bytes32 hash = entryPoint.getUserOpHash(op);
        {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(
                guardianKeyPriv,
                ECDSA.toEthSignedMessageHash(keccak256(bytes.concat(bytes6(uint48(pausedUntil)), hash)))
            );
            bytes memory sig = abi.encodePacked(r, s, v);

            op.signature = bytes.concat(op.signature, bytes6(uint48(pausedUntil)), sig);
        }

        ops[0] = op;
        logGas(op);
        entryPoint.handleOps(ops, beneficiary);
        assertEq(kernel.getDisabledMode(), bytes4(0xffffffff));
        assertEq(address(kernel.getDefaultValidator()), address(killSwitch));
        op = entryPoint.fillUserOp(address(kernel), abi.encodeWithSelector(KillSwitchAction.toggleKillSwitch.selector));

        op.signature = bytes.concat(bytes4(0), entryPoint.signUserOpHash(vm, guardianKeyPriv, op));
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);
        assertEq(kernel.getDisabledMode(), bytes4(0));
    }

    function test_mode_2() external {
        UserOperation memory op = entryPoint.fillUserOp(
            address(kernel), abi.encodeWithSelector(Kernel.execute.selector, owner, 0, "", Operation.Call)
        );

        op.signature = bytes.concat(bytes4(0), entryPoint.signUserOpHash(vm, ownerKey, op));
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);

        op = entryPoint.fillUserOp(address(kernel), abi.encodeWithSelector(KillSwitchAction.toggleKillSwitch.selector));
        address guardianKeyAddr;
        uint256 guardianKeyPriv;
        (guardianKeyAddr, guardianKeyPriv) = makeAddrAndKey("guardianKey");
        bytes memory enableData = abi.encodePacked(guardianKeyAddr);
        {
            bytes32 digest = getTypedDataHash(
                address(kernel),
                KillSwitchAction.toggleKillSwitch.selector,
                0,
                0,
                address(killSwitch),
                address(action),
                enableData
            );
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);

            op.signature = abi.encodePacked(
                bytes4(0x00000002),
                uint48(0),
                uint48(0),
                address(killSwitch),
                address(action),
                uint256(enableData.length),
                enableData,
                uint256(65),
                r,
                s,
                v
            );
        }

        uint256 pausedUntil = block.timestamp + 1000;

        bytes32 hash = entryPoint.getUserOpHash(op);
        {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(
                guardianKeyPriv,
                ECDSA.toEthSignedMessageHash(keccak256(bytes.concat(bytes6(uint48(pausedUntil)), hash)))
            );
            bytes memory sig = abi.encodePacked(r, s, v);

            op.signature = bytes.concat(op.signature, bytes6(uint48(pausedUntil)), sig);
        }

        ops[0] = op;
        logGas(op);
        entryPoint.handleOps(ops, beneficiary);
        assertEq(address(kernel.getDefaultValidator()), address(killSwitch));
        op = entryPoint.fillUserOp(
            address(kernel), abi.encodeWithSelector(Kernel.execute.selector, owner, 0, "", Operation.Call)
        );

        op.signature = bytes.concat(bytes4(0), entryPoint.signUserOpHash(vm, ownerKey, op));
        ops[0] = op;
        vm.expectRevert();
        entryPoint.handleOps(ops, beneficiary); // should revert because kill switch is active
        vm.warp(pausedUntil + 1);
        entryPoint.handleOps(ops, beneficiary); // should not revert because pausedUntil has been passed
    }
}
