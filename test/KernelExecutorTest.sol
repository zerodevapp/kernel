pragma solidity ^0.8.0;

import {LibERC7579} from "solady/accounts/LibERC7579.sol";
import {Install, Call, InstallAndExecute} from "src/types/Structs.sol";
import {ERC1967_IMPLEMENTATION_SLOT} from "src/types/Constants.sol";
import {MockExecutor} from "./mock/MockExecutor.sol";
import {MockCallee} from "./mock/MockCallee.sol";
import {MockKernel} from "./mock/MockKernel.sol";
import {KernelTestBase} from "./KernelTestBase.sol";

abstract contract KernelExecutorTest is KernelTestBase {
    function test_execute_from_executor_fail_not_executor() external {
        address notExecutor = makeAddr("not executor");
        vm.startPrank(notExecutor);
        vm.expectRevert();
        kernel.executeFromExecutor(
            bytes32(0), abi.encodePacked(address(callee), uint256(0), abi.encodeWithSelector(MockCallee.foo.selector))
        );
    }

    function test_install_executor_oninstall_success() external unitTest {
        assertTrue(kernel.supportsModule(2));
        address newEx = address(new MockExecutor());
        kernel.installModule(2, newEx, abi.encode(hex"deadbeef", ""));
        assertEq(address(kernel.executorConfig(newEx).hook), address(1));
        assertTrue(kernel.isModuleInstalled(2, newEx, hex""));
    }

    function test_install_executor_oninstall_fail() external unitTest {
        address newEx = makeAddr("New Executor");
        kernel.installModule(2, newEx, abi.encode(hex"", ""));
        assertEq(address(kernel.executorConfig(newEx).hook), address(1));
        assertTrue(kernel.isModuleInstalled(2, newEx, hex""));
    }

    function test_uninstall_executor_onuninstall_success() external unitTest {
        address newEx = address(new MockExecutor());
        kernel.installModule(2, newEx, abi.encode(hex"deadbeef", ""));
        assertEq(address(kernel.executorConfig(newEx).hook), address(1));
        kernel.uninstallModule(2, newEx, abi.encode(hex"", hex""));
        assertEq(address(kernel.executorConfig(newEx).hook), address(0));
    }

    function test_uninstall_executor_onuninstall_fail() external unitTest {
        address newEx = makeAddr("New Executor");
        kernel.installModule(2, newEx, abi.encode(hex"", ""));
        assertEq(address(kernel.executorConfig(newEx).hook), address(1));
        kernel.uninstallModule(2, newEx, abi.encode(hex"", hex""));
        assertEq(address(kernel.executorConfig(newEx).hook), address(0));
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
