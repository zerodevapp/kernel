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

using ERC4337Utils for IEntryPoint;

contract KillSwitchValidatorTest is KernelECDSATest {
    KillSwitchValidator killSwitch;
    KillSwitchAction action;
    address guardian;
    uint256 guardianKey;

    function setUp() public override {
        killSwitch = new KillSwitchValidator();
        action = new KillSwitchAction(killSwitch);
        super.setUp();
        (guardian, guardianKey) = makeAddrAndKey("guardian");
    }

    function _setExecutionDetail() internal override {
        executionDetail.executor = address(action);
        executionSig = KillSwitchAction.toggleKillSwitch.selector;
        executionDetail.validator = killSwitch;
    }

    function getEnableData() internal view override returns (bytes memory) {
        return abi.encodePacked(guardian);
    }

    function getValidatorSignature(UserOperation memory _op) internal view override returns (bytes memory sig) {
        uint256 pausedUntil = block.timestamp + 1000;

        bytes32 hash = entryPoint.getUserOpHash(_op);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            guardianKey, ECDSA.toEthSignedMessageHash(keccak256(bytes.concat(bytes6(uint48(pausedUntil)), hash)))
        );
        sig = abi.encodePacked(uint48(pausedUntil), r, s, v);
    }

    function test_should_fail_with_not_implemented_isValidSignature() public {
        test_should_fail_with_not_implemented_isValidSignature(
            bytes32(keccak256(abi.encodePacked("HelloWorld"))), abi.encodePacked("HelloWorld")
        );
    }

    function test_should_fail_with_not_implemented_isValidSignature(bytes32 hash, bytes memory sig) public {
        vm.expectRevert();
        killSwitch.validateSignature(hash, sig);
    }

    function test_should_fail_with_not_implemented_validCaller() public {
        test_should_fail_with_not_implemented_validCaller(address(0), abi.encodePacked("HelloWorld"));
    }

    function test_should_fail_with_not_implemented_validCaller(address caller, bytes memory data) public {
        vm.expectRevert();
        killSwitch.validCaller(caller, data);
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
        bytes memory enableData = abi.encodePacked(guardian);
        {
            bytes32 digest = getTypedDataHash(
                KillSwitchAction.toggleKillSwitch.selector, 0, 0, address(killSwitch), address(action), enableData
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
        uint48 pausedUntil = uint48(block.timestamp + 1000);
        bytes32 hash = entryPoint.getUserOpHash(op);
        {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(
                guardianKey, ECDSA.toEthSignedMessageHash(keccak256(bytes.concat(bytes6(uint48(pausedUntil)), hash)))
            );
            bytes memory sig = abi.encodePacked(r, s, v);

            op.signature = bytes.concat(op.signature, bytes6(uint48(pausedUntil)), sig);
        }

        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);
        assertEq(kernel.getDisabledMode(), bytes4(0xffffffff));
        assertEq(address(kernel.getDefaultValidator()), address(killSwitch));
        op = entryPoint.fillUserOp(address(kernel), abi.encodeWithSelector(KillSwitchAction.toggleKillSwitch.selector));

        op.signature = bytes.concat(bytes4(0), entryPoint.signUserOpHash(vm, guardianKey, op));
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);
        assertEq(kernel.getDisabledMode(), bytes4(0));
    }
}
