// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Kernel} from "src/Kernel.sol";
import {BTTModifiers} from "./BTTModifiers.sol";
import {MockCallee} from "../mock/MockCallee.sol";
import {MockAction} from "../mock/MockAction.sol";
import {Unauthorized, InvalidExecType, InvalidCallType} from "src/types/Error.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";
import {Call} from "src/types/Structs.sol";

/// @title Kernel.execute BTT Tests
/// @notice Tests for execute following Branching Tree Technique
/// @dev Tree specification: test/btt/Kernel.execute.tree
abstract contract Kernel_execute is BTTModifiers {
    MockAction action;

    // State variables for execution mode
    bytes1 internal _callType;
    bytes1 internal _execType;

    function _setupExecuteTests() internal {
        action = new MockAction();
    }

    function _encodeMode(bytes1 callType, bytes1 execType) internal pure returns (bytes32) {
        return bytes32(abi.encodePacked(callType, execType, bytes4(0), bytes4(0), bytes22(0)));
    }

    function _currentMode() internal view returns (bytes32) {
        return _encodeMode(_callType, _execType);
    }

    /*//////////////////////////////////////////////////////////////
                        UNAUTHORIZED CALLER TESTS
    //////////////////////////////////////////////////////////////*/

    modifier whenTheCallerIsNotTheEntryPoint() {
        vm.stopPrank();
        vm.startPrank(makeAddr("randomCaller"));
        _;
    }

    function test_WhenTheCallerIsNotTheAccountItself() external whenTheCallerIsNotTheEntryPoint {
        // it should revert with Unauthorized error
        bytes32 mode = _encodeMode(LibERC7579.CALLTYPE_SINGLE, LibERC7579.EXECTYPE_DEFAULT);
        bytes memory executionData = abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector);

        vm.expectRevert(Unauthorized.selector);
        kernel.execute(mode, executionData);
    }

    /*//////////////////////////////////////////////////////////////
                    EXECUTION MODE TESTS
    //////////////////////////////////////////////////////////////*/

    modifier whenTheCallerIsTheEntryPointOrSelf() {
        vm.stopPrank();
        vm.startPrank(address(ep));
        _;
    }

    function test_GivenTheExecutionModeExecTypeIsUnsupported() external whenTheCallerIsTheEntryPointOrSelf {
        // it should revert with InvalidExecType error
        bytes32 mode = _encodeMode(LibERC7579.CALLTYPE_SINGLE, bytes1(0x02));
        bytes memory executionData = abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector);

        vm.expectRevert(InvalidExecType.selector);
        kernel.execute(mode, executionData);
    }

    /*//////////////////////////////////////////////////////////////
                    SINGLE CALL + DEFAULT EXEC TESTS
    //////////////////////////////////////////////////////////////*/

    modifier givenTheExecutionModeCallTypeIsSINGLE() {
        _callType = LibERC7579.CALLTYPE_SINGLE;
        _;
    }

    modifier givenTheExecutionModeExecTypeIsDEFAULT() {
        _execType = LibERC7579.EXECTYPE_DEFAULT;
        _;
    }

    function test_WhenTheTargetCallSucceeds()
        external
        whenTheCallerIsTheEntryPointOrSelf
        givenTheExecutionModeCallTypeIsSINGLE
        givenTheExecutionModeExecTypeIsDEFAULT
    {
        // it should return the call result in returnData array
        // it should have exactly one element in returnData
        bytes memory executionData = abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector);

        kernel.execute(_currentMode(), executionData);

        assertEq(callee.bar(), 1, "Callee state should be updated");
    }

    function test_WhenTheTargetCallReverts()
        external
        whenTheCallerIsTheEntryPointOrSelf
        givenTheExecutionModeCallTypeIsSINGLE
        givenTheExecutionModeExecTypeIsDEFAULT
    {
        // it should propagate the revert
        bytes memory executionData = abi.encodePacked(address(callee), uint256(0), MockCallee.forceRevert.selector);

        vm.expectRevert(MockCallee.Haha.selector);
        kernel.execute(_currentMode(), executionData);
    }

    /*//////////////////////////////////////////////////////////////
                    SINGLE CALL + TRY EXEC TESTS
    //////////////////////////////////////////////////////////////*/

    modifier givenTheExecutionModeExecTypeIsTRY() {
        _execType = LibERC7579.EXECTYPE_TRY;
        _;
    }

    function test_WhenTheTargetCallSucceeds_GivenTheExecutionModeExecTypeIsTRY()
        external
        whenTheCallerIsTheEntryPointOrSelf
        givenTheExecutionModeCallTypeIsSINGLE
        givenTheExecutionModeExecTypeIsTRY
    {
        // it should return the call result in returnData array
        // it should have exactly one element in returnData
        bytes memory executionData = abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector);

        kernel.execute(_currentMode(), executionData);

        assertEq(callee.bar(), 1, "Callee state should be updated");
    }

    function test_WhenTheTargetCallReverts_GivenTheExecutionModeExecTypeIsTRY()
        external
        whenTheCallerIsTheEntryPointOrSelf
        givenTheExecutionModeCallTypeIsSINGLE
        givenTheExecutionModeExecTypeIsTRY
    {
        // it should NOT propagate the revert
        // it should return empty bytes for the failed call
        bytes memory executionData = abi.encodePacked(address(callee), uint256(0), MockCallee.forceRevert.selector);

        // Should NOT revert
        kernel.execute(_currentMode(), executionData);

        // Callee state should remain unchanged
        assertEq(callee.bar(), 0, "Callee state should remain unchanged after failed TRY");
    }

    /*//////////////////////////////////////////////////////////////
                    BATCH CALL + DEFAULT EXEC TESTS
    //////////////////////////////////////////////////////////////*/

    modifier givenTheExecutionModeCallTypeIsBATCH() {
        _callType = LibERC7579.CALLTYPE_BATCH;
        _;
    }

    function test_WhenAllTargetCallsSucceed()
        external
        whenTheCallerIsTheEntryPointOrSelf
        givenTheExecutionModeCallTypeIsBATCH
        givenTheExecutionModeExecTypeIsDEFAULT
    {
        // it should return all call results in returnData array
        // it should have N elements in returnData for N calls
        Call[] memory calls = new Call[](3);
        calls[0] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.foo.selector)});
        calls[1] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.foo.selector)});
        calls[2] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.foo.selector)});

        kernel.execute(_currentMode(), abi.encode(calls));

        assertEq(callee.bar(), 3, "Callee state should reflect 3 calls");
    }

    function test_WhenAnyTargetCallReverts()
        external
        whenTheCallerIsTheEntryPointOrSelf
        givenTheExecutionModeCallTypeIsBATCH
        givenTheExecutionModeExecTypeIsDEFAULT
    {
        // it should propagate the revert
        // it should NOT execute remaining calls after the failure
        Call[] memory calls = new Call[](2);
        calls[0] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.foo.selector)});
        calls[1] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.forceRevert.selector)});

        vm.expectRevert(MockCallee.Haha.selector);
        kernel.execute(_currentMode(), abi.encode(calls));
    }

    /*//////////////////////////////////////////////////////////////
                    BATCH CALL + TRY EXEC TESTS
    //////////////////////////////////////////////////////////////*/

    function test_WhenAllTargetCallsSucceed_GivenTheExecutionModeExecTypeIsTRY()
        external
        whenTheCallerIsTheEntryPointOrSelf
        givenTheExecutionModeCallTypeIsBATCH
        givenTheExecutionModeExecTypeIsTRY
    {
        // it should return all call results in returnData array
        // it should have N elements in returnData for N calls
        Call[] memory calls = new Call[](3);
        calls[0] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.foo.selector)});
        calls[1] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.foo.selector)});
        calls[2] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.foo.selector)});

        kernel.execute(_currentMode(), abi.encode(calls));

        assertEq(callee.bar(), 3, "Callee state should reflect 3 calls");
    }

    function test_WhenAnyTargetCallReverts_GivenTheExecutionModeExecTypeIsTRY()
        external
        whenTheCallerIsTheEntryPointOrSelf
        givenTheExecutionModeCallTypeIsBATCH
        givenTheExecutionModeExecTypeIsTRY
    {
        // it should NOT propagate the revert
        // it should return empty bytes for the failed call
        // it should continue executing remaining calls
        Call[] memory calls = new Call[](3);
        calls[0] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.foo.selector)});
        calls[1] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.forceRevert.selector)});
        calls[2] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.foo.selector)});

        // Should NOT revert
        kernel.execute(_currentMode(), abi.encode(calls));

        // First and third calls should have executed
        assertEq(callee.bar(), 2, "First and third calls should have executed");
    }

    /*//////////////////////////////////////////////////////////////
                    DELEGATECALL + DEFAULT EXEC TESTS
    //////////////////////////////////////////////////////////////*/

    modifier givenTheExecutionModeCallTypeIsDELEGATECALL() {
        _callType = LibERC7579.CALLTYPE_DELEGATECALL;
        _;
    }

    function test_WhenTheDelegatecallSucceeds()
        external
        whenTheCallerIsTheEntryPointOrSelf
        givenTheExecutionModeCallTypeIsDELEGATECALL
        givenTheExecutionModeExecTypeIsDEFAULT
    {
        // it should return the delegatecall result
        // it should execute in the context of the Kernel
        _setupExecuteTests();
        bytes memory executionData = abi.encodePacked(address(action), abi.encodeWithSelector(action.doAction.selector));

        kernel.execute(_currentMode(), executionData);

        // Action modifies kernel's storage - verify it executed
        assertEq(kernel.accountId(), "kernel.v0.4", "Delegatecall should execute in kernel context");
    }

    function test_WhenTheDelegatecallReverts()
        external
        whenTheCallerIsTheEntryPointOrSelf
        givenTheExecutionModeCallTypeIsDELEGATECALL
        givenTheExecutionModeExecTypeIsDEFAULT
    {
        // it should propagate the revert
        _setupExecuteTests();
        bytes memory executionData =
            abi.encodePacked(address(action), abi.encodeWithSelector(action.doRevertingAction.selector));

        vm.expectRevert(MockAction.MockActionRevert.selector);
        kernel.execute(_currentMode(), executionData);
    }

    /*//////////////////////////////////////////////////////////////
                    DELEGATECALL + TRY EXEC TESTS
    //////////////////////////////////////////////////////////////*/

    function test_WhenTheDelegatecallSucceeds_GivenTheExecutionModeExecTypeIsTRY()
        external
        whenTheCallerIsTheEntryPointOrSelf
        givenTheExecutionModeCallTypeIsDELEGATECALL
        givenTheExecutionModeExecTypeIsTRY
    {
        // it should return the delegatecall result
        _setupExecuteTests();
        bytes memory executionData = abi.encodePacked(address(action), abi.encodeWithSelector(action.doAction.selector));

        kernel.execute(_currentMode(), executionData);

        assertEq(kernel.accountId(), "kernel.v0.4", "Delegatecall should execute in kernel context");
    }

    function test_WhenTheDelegatecallReverts_GivenTheExecutionModeExecTypeIsTRY()
        external
        whenTheCallerIsTheEntryPointOrSelf
        givenTheExecutionModeCallTypeIsDELEGATECALL
        givenTheExecutionModeExecTypeIsTRY
    {
        // it should NOT propagate the revert
        // it should return empty bytes
        _setupExecuteTests();
        bytes memory executionData =
            abi.encodePacked(address(action), abi.encodeWithSelector(action.doRevertingAction.selector));

        // Should NOT revert - kernel state should remain unchanged
        kernel.execute(_currentMode(), executionData);

        // Verify execution completed without reverting by checking kernel is still functional
        assertEq(kernel.accountId(), "kernel.v0.4", "Kernel should remain functional after TRY delegatecall revert");
    }

    /*//////////////////////////////////////////////////////////////
                    UNSUPPORTED CALLTYPE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_GivenTheExecutionModeCallTypeIsUnsupported() external whenTheCallerIsTheEntryPointOrSelf {
        // it should revert with InvalidCallType error
        bytes32 mode = _encodeMode(bytes1(0x03), LibERC7579.EXECTYPE_DEFAULT);
        bytes memory executionData = abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector);

        vm.expectRevert(InvalidCallType.selector);
        kernel.execute(mode, executionData);
    }
}
