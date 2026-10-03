// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {Kernel} from "src/Kernel.sol";
import {Kernel7702} from "src/Kernel7702.sol";
import {Unauthorized, UnauthorizedCallData} from "src/types/Error.sol";

/// @notice TOB-KERNEL-13 regression: executeUserOp loads its transient validation-scoped hook by
///         the supplied userOpHash. Nothing binds that hash to the operation being executed, so any
///         path that lets already-executing calldata reenter executeUserOp with a fresh hash skips
///         the hook for the nested calldata. Both reentry paths must be closed: the external
///         self-call (EntryPoint-only auth) and the delegatecall-nested wrapper (selector block).
contract ExecuteUserOpBindingTest is Test {
    IEntryPoint ep;
    Kernel kernel;

    function setUp() public {
        ep = EntryPointLib.deploy();
        Kernel7702 template = new Kernel7702(ep);
        address eoa = makeAddr("Owner");
        vm.etch(eoa, abi.encodePacked(bytes3(0xef0100), address(template)));
        kernel = Kernel(payable(eoa));
        vm.deal(eoa, 1 ether);
    }

    function test_SelfCallIsRejected() external {
        PackedUserOperation memory op = _emptyOp();
        vm.prank(address(kernel));
        vm.expectRevert(Unauthorized.selector);
        kernel.executeUserOp(op, keccak256("unrelated hash"));
    }

    function test_NestedExecuteUserOpIsRejectedAtValidation() external {
        PackedUserOperation memory op = _emptyOp();
        // executeUserOp wrapping executeUserOp: the inner one would be delegatecalled with an
        // attacker-chosen hash while msg.sender is still the EntryPoint.
        op.callData = abi.encodePacked(Kernel.executeUserOp.selector, Kernel.executeUserOp.selector);

        vm.prank(address(ep));
        vm.expectRevert(UnauthorizedCallData.selector);
        kernel.validateUserOp(op, keccak256("op hash"), 0);
    }

    function _emptyOp() internal view returns (PackedUserOperation memory op) {
        op.sender = address(kernel);
        op.callData = abi.encodePacked(Kernel.execute.selector);
        op.accountGasLimits = bytes32(uint256(1_000_000) << 128 | uint256(1_000_000));
        op.gasFees = bytes32(uint256(1) << 128 | uint256(1));
    }
}
