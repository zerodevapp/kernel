// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {BTTModifiers} from "./BTTModifiers.sol";
import {Unauthorized, InvalidExecType, InvalidCallType} from "src/types/Error.sol";
import {MockExecutor} from "../mock/MockExecutor.sol";
import {MockCallee} from "../mock/MockCallee.sol";
import {MockAction} from "../mock/MockAction.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";
import {Call} from "src/types/Structs.sol";

abstract contract Kernel_executeFromExecutor is BTTModifiers {
    MockExecutor testExecutor;

    // State variables for execution mode - used by tests to build mode
    bytes1 internal _executorCallType;
    bytes1 internal _executorExecType;

    function _setupExecutorTests() internal {
        testExecutor = new MockExecutor();
        vm.stopPrank();
        vm.startPrank(address(ep));
        kernel.installModule(2, address(testExecutor), abi.encode(hex"", hex""));
        vm.stopPrank();
    }

    function test_WhenTheCallerIsNotAnInstalledExecutor() external {
        // it should revert with Unauthorized error
        MockExecutor uninstalledExecutor = new MockExecutor();

        vm.expectRevert(Unauthorized.selector);
        uninstalledExecutor.executeViaKernel(
            kernel, LibERC7579.CALLTYPE_SINGLE, LibERC7579.EXECTYPE_DEFAULT, address(callee), 0, MockCallee.foo.selector
        );
    }

    modifier whenTheCallerIsAnInstalledExecutor() {
        _setupExecutorTests();
        _;
    }

    function test_GivenTheExecutionModeExecTypeIsUnsupported() external whenTheCallerIsAnInstalledExecutor {
        // it should revert with InvalidExecType error
        vm.expectRevert(InvalidExecType.selector);
        testExecutor.executeViaKernel(
            kernel, LibERC7579.CALLTYPE_SINGLE, bytes1(0x02), address(callee), 0, MockCallee.foo.selector
        );
    }

    modifier givenTheExecutionModeCallTypeIsSINGLE() {
        _executorCallType = LibERC7579.CALLTYPE_SINGLE;
        _;
    }

    modifier givenTheExecutionModeExecTypeIsDEFAULT() {
        _executorExecType = LibERC7579.EXECTYPE_DEFAULT;
        _;
    }

    function test_WhenTheTargetCallSucceeds()
        external
        whenTheCallerIsAnInstalledExecutor
        givenTheExecutionModeCallTypeIsSINGLE
        givenTheExecutionModeExecTypeIsDEFAULT
    {
        // it should return the result in returnData array
        assertEq(_executorCallType, LibERC7579.CALLTYPE_SINGLE, "Call type should be SINGLE");
        assertEq(_executorExecType, LibERC7579.EXECTYPE_DEFAULT, "Exec type should be DEFAULT");

        bytes[] memory results = testExecutor.executeViaKernel(
            kernel, _executorCallType, _executorExecType, address(callee), 0, MockCallee.foo.selector
        );

        assertEq(results.length, 1, "Should return one result");
        assertEq(callee.bar(), 1, "Callee should be called");
    }

    function test_WhenTheTargetCallReverts()
        external
        whenTheCallerIsAnInstalledExecutor
        givenTheExecutionModeCallTypeIsSINGLE
        givenTheExecutionModeExecTypeIsDEFAULT
    {
        // it should propagate the revert
        assertEq(_executorCallType, LibERC7579.CALLTYPE_SINGLE, "Call type should be SINGLE");

        vm.expectRevert(MockCallee.Haha.selector);
        testExecutor.executeViaKernel(
            kernel, _executorCallType, _executorExecType, address(callee), 0, MockCallee.forceRevert.selector
        );
    }

    modifier givenTheExecutionModeExecTypeIsTRY() {
        _executorExecType = LibERC7579.EXECTYPE_TRY;
        _;
    }

    function test_WhenTheTargetCallSucceeds_GivenTheExecutionModeExecTypeIsTRY()
        external
        whenTheCallerIsAnInstalledExecutor
        givenTheExecutionModeCallTypeIsSINGLE
        givenTheExecutionModeExecTypeIsTRY
    {
        // it should return the result in returnData array
        assertEq(_executorExecType, LibERC7579.EXECTYPE_TRY, "Exec type should be TRY");

        bytes[] memory results = testExecutor.executeViaKernel(
            kernel, _executorCallType, _executorExecType, address(callee), 0, MockCallee.foo.selector
        );

        assertEq(results.length, 1, "Should return one result");
        assertEq(callee.bar(), 1, "Callee should be called");
    }

    function test_WhenTheTargetCallReverts_GivenTheExecutionModeExecTypeIsTRY()
        external
        whenTheCallerIsAnInstalledExecutor
        givenTheExecutionModeCallTypeIsSINGLE
        givenTheExecutionModeExecTypeIsTRY
    {
        // it should NOT propagate the revert
        // it should return empty bytes for the failed call
        assertEq(_executorExecType, LibERC7579.EXECTYPE_TRY, "Exec type should be TRY");

        bytes[] memory results = testExecutor.executeViaKernel(
            kernel, _executorCallType, _executorExecType, address(callee), 0, MockCallee.forceRevert.selector
        );

        assertEq(results.length, 1, "Should return one result");
        assertEq(callee.bar(), 0, "Callee should NOT be called");
    }

    modifier givenTheExecutionModeCallTypeIsBATCH() {
        _executorCallType = LibERC7579.CALLTYPE_BATCH;
        _;
    }

    function test_WhenAllCallsSucceed()
        external
        whenTheCallerIsAnInstalledExecutor
        givenTheExecutionModeCallTypeIsBATCH
        givenTheExecutionModeExecTypeIsDEFAULT
    {
        // it should return all results in returnData array
        assertEq(_executorCallType, LibERC7579.CALLTYPE_BATCH, "Call type should be BATCH");

        bytes[] memory results = testExecutor.executeBatchViaKernel(kernel, _executorExecType, 3);

        assertEq(results.length, 3, "Should return three results");
        // Note: MockExecutor.executeBatchViaKernel calls kernel.accountId(), not callee
    }

    function test_WhenAnyCallReverts()
        external
        whenTheCallerIsAnInstalledExecutor
        givenTheExecutionModeCallTypeIsBATCH
        givenTheExecutionModeExecTypeIsDEFAULT
    {
        // it should propagate the revert
        assertEq(_executorExecType, LibERC7579.EXECTYPE_DEFAULT, "Exec type should be DEFAULT");

        vm.expectRevert(MockCallee.Haha.selector);
        testExecutor.executeBatchWithRevertViaKernel(kernel, _executorExecType);
    }

    function test_WhenAllCallsSucceed_GivenTheExecutionModeExecTypeIsTRY()
        external
        whenTheCallerIsAnInstalledExecutor
        givenTheExecutionModeCallTypeIsBATCH
        givenTheExecutionModeExecTypeIsTRY
    {
        // it should return all results in returnData array
        assertEq(_executorExecType, LibERC7579.EXECTYPE_TRY, "Exec type should be TRY");

        bytes[] memory results = testExecutor.executeBatchViaKernel(kernel, _executorExecType, 3);

        assertEq(results.length, 3, "Should return three results");
        // Note: MockExecutor.executeBatchViaKernel calls kernel.accountId(), not callee
    }

    function test_WhenAnyCallReverts_GivenTheExecutionModeExecTypeIsTRY()
        external
        whenTheCallerIsAnInstalledExecutor
        givenTheExecutionModeCallTypeIsBATCH
        givenTheExecutionModeExecTypeIsTRY
    {
        // it should NOT propagate the revert
        // it should return empty bytes for the failed call
        // it should continue executing remaining calls
        assertEq(_executorExecType, LibERC7579.EXECTYPE_TRY, "Exec type should be TRY");

        bytes[] memory results = testExecutor.executeBatchWithRevertViaKernel(kernel, _executorExecType);

        assertEq(results.length, 3, "Should return three results");
        // First and third calls succeed (kernel.accountId()), second reverts (forceRevert)
        // Note: MockExecutor calls kernel.accountId() for first and third, not callee
    }

    modifier givenTheExecutionModeCallTypeIsDELEGATECALL() {
        _executorCallType = LibERC7579.CALLTYPE_DELEGATECALL;
        _;
    }

    function test_WhenTheDelegatecallSucceeds()
        external
        whenTheCallerIsAnInstalledExecutor
        givenTheExecutionModeCallTypeIsDELEGATECALL
        givenTheExecutionModeExecTypeIsDEFAULT
    {
        // it should return the result
        assertEq(_executorCallType, LibERC7579.CALLTYPE_DELEGATECALL, "Call type should be DELEGATECALL");

        bytes[] memory results = testExecutor.executeDelegatecallViaKernel(kernel, _executorExecType, false);

        assertEq(results.length, 1, "Should return one result");
    }

    function test_WhenTheDelegatecallReverts()
        external
        whenTheCallerIsAnInstalledExecutor
        givenTheExecutionModeCallTypeIsDELEGATECALL
        givenTheExecutionModeExecTypeIsDEFAULT
    {
        // it should propagate the revert
        assertEq(_executorExecType, LibERC7579.EXECTYPE_DEFAULT, "Exec type should be DEFAULT");

        vm.expectRevert(MockAction.MockActionRevert.selector);
        testExecutor.executeDelegatecallViaKernel(kernel, _executorExecType, true);
    }

    function test_WhenTheDelegatecallSucceeds_GivenTheExecutionModeExecTypeIsTRY()
        external
        whenTheCallerIsAnInstalledExecutor
        givenTheExecutionModeCallTypeIsDELEGATECALL
        givenTheExecutionModeExecTypeIsTRY
    {
        // it should return the result
        assertEq(_executorExecType, LibERC7579.EXECTYPE_TRY, "Exec type should be TRY");

        bytes[] memory results = testExecutor.executeDelegatecallViaKernel(kernel, _executorExecType, false);

        assertEq(results.length, 1, "Should return one result");
    }

    function test_WhenTheDelegatecallReverts_GivenTheExecutionModeExecTypeIsTRY()
        external
        whenTheCallerIsAnInstalledExecutor
        givenTheExecutionModeCallTypeIsDELEGATECALL
        givenTheExecutionModeExecTypeIsTRY
    {
        // it should NOT propagate the revert
        // it should return empty bytes
        assertEq(_executorExecType, LibERC7579.EXECTYPE_TRY, "Exec type should be TRY");

        bytes[] memory results = testExecutor.executeDelegatecallViaKernel(kernel, _executorExecType, true);

        assertEq(results.length, 1, "Should return one result");
    }

    function test_GivenTheExecutionModeCallTypeIsUnsupported() external whenTheCallerIsAnInstalledExecutor {
        // it should revert with InvalidCallType error
        vm.expectRevert(InvalidCallType.selector);
        testExecutor.executeViaKernelWithCallType(kernel, bytes1(0x03), LibERC7579.EXECTYPE_DEFAULT);
    }
}
