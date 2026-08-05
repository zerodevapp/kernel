pragma solidity ^0.8.0;

import {LibERC7579} from "solady/accounts/LibERC7579.sol";
import {Call} from "src/types/Structs.sol";
import {MockExecutor} from "./mock/MockExecutor.sol";
import {MockCallee} from "./mock/MockCallee.sol";
import {KernelTestBase} from "./KernelTestBase.sol";
import {Unauthorized, InvalidDataLength, ScopedExecutionHookStillInstalled} from "src/types/Error.sol";
import {SCOPED_EXECUTION_HOOK_EXECUTOR_SCOPE} from "src/types/Constants.sol";
import {
    executorScopedExecutionHookId,
    getScopedExecutionHookScope,
    getScopedExecutionHookExecutor
} from "src/lib/Utils.sol";

abstract contract KernelExecutorTest is KernelTestBase {
    function test_execute_from_executor_fail_not_executor() external {
        address notExecutor = makeAddr("not executor");
        vm.startPrank(notExecutor);
        vm.expectRevert(Unauthorized.selector);
        kernel.executeFromExecutor(
            bytes32(0), abi.encodePacked(address(callee), uint256(0), abi.encodeWithSelector(MockCallee.foo.selector))
        );
    }

    function test_install_executor_oninstall_success() external unitTest {
        assertTrue(kernel.supportsModule(2));
        address newEx = address(new MockExecutor());
        kernel.installModule(2, newEx, abi.encode(hex"deadbeef", ""));
        assertTrue(kernel.executorConfig(newEx).installed);
        assertTrue(kernel.isModuleInstalled(2, newEx, hex""));
    }

    function test_install_executor_oninstall_fail() external unitTest {
        address newEx = makeAddr("New Executor");
        kernel.installModule(2, newEx, abi.encode(hex"", ""));
        assertTrue(kernel.executorConfig(newEx).installed);
        assertTrue(kernel.isModuleInstalled(2, newEx, hex""));
    }

    function test_install_executor_rejects_legacy_hook_data() external unitTest {
        MockExecutor newEx = new MockExecutor();
        vm.expectRevert(InvalidDataLength.selector);
        kernel.installModule(2, address(newEx), abi.encode(hex"", abi.encodePacked(address(1))));
    }

    function test_uninstall_executor_onuninstall_success() external unitTest {
        address newEx = address(new MockExecutor());
        kernel.installModule(2, newEx, abi.encode(hex"deadbeef", ""));
        assertTrue(kernel.executorConfig(newEx).installed);
        kernel.uninstallModule(2, newEx, abi.encode(hex"", hex""));
        assertFalse(kernel.executorConfig(newEx).installed);
    }

    function test_uninstall_executor_onuninstall_fail() external unitTest {
        address newEx = makeAddr("New Executor");
        kernel.installModule(2, newEx, abi.encode(hex"", ""));
        assertTrue(kernel.executorConfig(newEx).installed);
        kernel.uninstallModule(2, newEx, abi.encode(hex"", hex""));
        assertFalse(kernel.executorConfig(newEx).installed);
    }

    function test_executor_scoped_execution_hook() external {
        bytes memory hookContext = abi.encodePacked(SCOPED_EXECUTION_HOOK_EXECUTOR_SCOPE, bytes20(executor));
        vm.startPrank(address(ep));
        kernel.installModule(11, address(hook), abi.encode(hex"deadbeef", hookContext));
        assertTrue(kernel.isModuleInstalled(11, address(hook), hookContext));
        assertEq(address(kernel.executorConfig(executor).scopedExecutionHook), address(hook));
        vm.stopPrank();

        vm.prank(executor);
        kernel.executeFromExecutor(
            bytes32(0), abi.encodePacked(address(callee), uint256(0), abi.encodeWithSelector(MockCallee.foo.selector))
        );
        bytes32 expectedId = executorScopedExecutionHookId(executor);
        assertEq(getScopedExecutionHookScope(expectedId), SCOPED_EXECUTION_HOOK_EXECUTOR_SCOPE);
        assertEq(getScopedExecutionHookExecutor(expectedId), executor);
        assertEq(hook.preCheckId(address(kernel)), expectedId);
        assertEq(hook.postCheckId(address(kernel)), expectedId);
        assertEq(callee.bar(), 1);

        vm.startPrank(address(ep));
        vm.expectRevert(ScopedExecutionHookStillInstalled.selector);
        kernel.uninstallModule(2, executor, abi.encode(hex"", hex""));
        kernel.uninstallModule(11, address(hook), abi.encode(hex"", hookContext));
        kernel.uninstallModule(2, executor, abi.encode(hex"", hex""));
        assertFalse(kernel.executorConfig(executor).installed);
        vm.stopPrank();
    }

    function test_execute_from_executor() external unitTestExecutor {
        vm.expectEmit(address(callee));
        emit MockCallee.Lorem();
        kernel.executeFromExecutor(
            bytes32(0), abi.encodePacked(address(callee), uint256(0), abi.encodeWithSelector(MockCallee.foo.selector))
        );
        assertEq(callee.bar(), 1);
    }

    function test_execute_batch_from_executor() external unitTestExecutor {
        Call[] memory calls = new Call[](2);
        calls[0] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.foo.selector)});
        calls[1] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.lorem.selector)});
        assertEq(callee.data(), "");
        vm.expectEmit(address(callee));
        emit MockCallee.Lorem();
        kernel.executeFromExecutor(
            LibERC7579.encodeMode(bytes1(0x01), bytes1(0x00), bytes4(0), bytes22(0)), abi.encode(calls)
        );
        assertEq(callee.bar(), 1);
        assertEq(callee.data(), "lorem ipsum");
    }

    function test_execute_delegatecall_from_executor() external unitTestExecutor {
        vm.expectEmit(address(kernel));
        emit MockCallee.Lorem();
        kernel.executeFromExecutor(
            LibERC7579.encodeMode(bytes1(0xff), bytes1(0x00), bytes4(0), bytes22(0)),
            abi.encodePacked(address(callee), abi.encodeWithSelector(MockCallee.foo.selector))
        );
    }
}
