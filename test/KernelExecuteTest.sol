pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {EntryPointLib} from "./utils/EntryPointLib.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Kernel} from "src/Kernel.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {KernelHelper} from "src/KernelHelper.sol";
import {SelectorManager} from "src/core/SelectorManager.sol";
import {KernelFactory} from "src/KernelFactory.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {KernelImmutableECDSA} from "src/KernelImmutableECDSA.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";
import {LibString} from "solady/utils/LibString.sol";
import {Install} from "src/types/Structs.sol";
import {MockFallback} from "./mock/MockFallback.sol";
import {MockExecutor} from "./mock/MockExecutor.sol";
import {MockValidator} from "./mock/MockValidator.sol";
import {MockHook} from "./mock/MockHook.sol";
import {MockPolicy} from "./mock/MockPolicy.sol";
import {MockSigner} from "./mock/MockSigner.sol";
import {MockERC721} from "./mock/MockERC721.sol";
import {MockERC1155} from "./mock/MockERC1155.sol";
import {MockCallee} from "./mock/MockCallee.sol";
import {MockKernel} from "./mock/MockKernel.sol";
import {IHook, IValidator} from "src/interfaces/IERC7579Modules.sol";
import {CallType} from "src/types/Types.sol";
import "src/types/Constants.sol";
import "forge-std/console.sol";
import "src/types/Error.sol";
import "src/types/Events.sol";
import "src/types/Structs.sol";
import {KernelTestBase} from "./KernelTestBase.sol";

abstract contract KernelExecuteTest is KernelTestBase {
    function test_execute() external unitTest {
        vm.expectEmit(address(callee));
        emit MockCallee.Lorem();
        assertEq(kernel.supportsExecutionMode(bytes32(0)), true);
        kernel.execute(
            bytes32(0), abi.encodePacked(address(callee), uint256(0), abi.encodeWithSelector(MockCallee.foo.selector))
        );
        assertEq(callee.bar(), 1);
    }

    function test_execute_fail() external unitTest {
        vm.expectRevert(MockCallee.Haha.selector);
        kernel.execute(
            bytes32(0),
            abi.encodePacked(address(callee), uint256(0), abi.encodeWithSelector(MockCallee.forceRevert.selector))
        );
    }

    function test_execute_fail_invalid_callType() external unitTest {
        bytes32 mode = LibERC7579.encodeMode(bytes1(0x02), bytes1(0x01), bytes4(0), bytes22(0));
        assertEq(kernel.supportsExecutionMode(mode), false);
        vm.expectRevert(InvalidCallType.selector, address(kernel));
        kernel.execute(
            mode, abi.encodePacked(address(callee), uint256(0), abi.encodeWithSelector(MockCallee.foo.selector))
        );
    }

    function test_execute_fail_invalid_execType() external unitTest {
        bytes32 mode = LibERC7579.encodeMode(bytes1(0x00), bytes1(0x02), bytes4(0), bytes22(0));
        assertEq(kernel.supportsExecutionMode(mode), false);
        vm.expectRevert(InvalidExecType.selector, address(kernel));
        kernel.execute(
            mode, abi.encodePacked(address(callee), uint256(0), abi.encodeWithSelector(MockCallee.foo.selector))
        );
    }

    function test_execute_fail_try() external unitTest {
        bytes32 mode = LibERC7579.encodeMode(bytes1(0x00), bytes1(0x01), bytes4(0), bytes22(0));
        assertEq(kernel.supportsExecutionMode(mode), true);
        kernel.execute(
            mode, abi.encodePacked(address(callee), uint256(0), abi.encodeWithSelector(MockCallee.forceRevert.selector))
        );
    }

    function test_execute_batch() external unitTest {
        Call[] memory calls = new Call[](2);
        calls[0] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.foo.selector)});
        calls[1] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.lorem.selector)});
        assertEq(callee.data(), "");
        bytes32 mode = LibERC7579.encodeMode(bytes1(0x01), bytes1(0x00), bytes4(0), bytes22(0));
        assertEq(kernel.supportsExecutionMode(mode), true);
        vm.expectEmit(address(callee));
        emit MockCallee.Lorem();
        kernel.execute(mode, abi.encode(calls));
        assertEq(callee.bar(), 1);
        assertEq(callee.data(), "lorem ipsum");
    }

    function test_execute_batch_fail() external unitTest {
        Call[] memory calls = new Call[](2);
        calls[0] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.foo.selector)});
        calls[1] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.forceRevert.selector)});
        assertEq(callee.data(), "");
        bytes32 mode = LibERC7579.encodeMode(bytes1(0x01), bytes1(0x00), bytes4(0), bytes22(0));
        assertEq(kernel.supportsExecutionMode(mode), true);
        vm.expectRevert(MockCallee.Haha.selector);
        kernel.execute(LibERC7579.encodeMode(bytes1(0x01), bytes1(0x00), bytes4(0), bytes22(0)), abi.encode(calls));
    }

    function test_execute_batch_fail_try() external unitTest {
        Call[] memory calls = new Call[](2);
        calls[0] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.foo.selector)});
        calls[1] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.forceRevert.selector)});
        assertEq(callee.data(), "");
        bytes32 mode = LibERC7579.encodeMode(bytes1(0x01), bytes1(0x01), bytes4(0), bytes22(0));
        assertEq(kernel.supportsExecutionMode(mode), true);
        kernel.execute(LibERC7579.encodeMode(bytes1(0x01), bytes1(0x01), bytes4(0), bytes22(0)), abi.encode(calls));
        assertEq(callee.bar(), 1);
    }

    function test_execute_delegatecall() external unitTest {
        bytes32 mode = LibERC7579.encodeMode(bytes1(0xff), bytes1(0x00), bytes4(0), bytes22(0));
        assertEq(kernel.supportsExecutionMode(mode), true);
        vm.expectEmit(address(kernel));
        emit MockCallee.Lorem();
        kernel.execute(
            LibERC7579.encodeMode(bytes1(0xff), bytes1(0x00), bytes4(0), bytes22(0)),
            abi.encodePacked(address(callee), abi.encodeWithSelector(MockCallee.foo.selector))
        );
    }

    function test_execute_delegatecall_fail() external unitTest {
        vm.expectRevert(MockCallee.Haha.selector);
        kernel.execute(
            LibERC7579.encodeMode(bytes1(0xff), bytes1(0x00), bytes4(0), bytes22(0)),
            abi.encodePacked(address(callee), abi.encodeWithSelector(MockCallee.forceRevert.selector))
        );
    }

    function test_execute_delegatecall_fail_try() external unitTest {
        bytes32 mode = LibERC7579.encodeMode(bytes1(0xff), bytes1(0x01), bytes4(0), bytes22(0));
        assertEq(kernel.supportsExecutionMode(mode), true);
        kernel.execute(
            LibERC7579.encodeMode(bytes1(0xff), bytes1(0x01), bytes4(0), bytes22(0)),
            abi.encodePacked(address(callee), abi.encodeWithSelector(MockCallee.forceRevert.selector))
        );
    }
}
