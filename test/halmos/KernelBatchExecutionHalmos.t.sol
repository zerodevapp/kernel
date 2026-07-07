pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Kernel} from "src/Kernel.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {KernelImmutableECDSA} from "src/KernelImmutableECDSA.sol";
import {KernelFactory} from "src/KernelFactory.sol";
import {Install, Call} from "src/types/Structs.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {MockValidator} from "../mock/MockValidator.sol";
import {MockCallee} from "../mock/MockCallee.sol";
import {MockExecutor} from "../mock/MockExecutor.sol";

/// @title KernelBatchExecutionHalmos
/// @notice Halmos formal verification tests for batch execution safety
contract KernelBatchExecutionHalmos is SymTest, Test {
    Kernel private kernel;
    IEntryPoint private ep;
    MockCallee private callee;
    MockExecutor private executor;

    function setUp() external {
        ep = EntryPointLib.deploy();
        KernelUUPS uups = new KernelUUPS(ep);
        KernelImmutableECDSA immutableEcdsa = new KernelImmutableECDSA(ep);
        KernelFactory factory = new KernelFactory(uups, immutableEcdsa);
        MockValidator rootValidator = new MockValidator();
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});
        kernel = factory.deploy(pkgs, 0);
        callee = new MockCallee();

        executor = new MockExecutor();
        vm.startPrank(address(ep));
        kernel.installModule(2, address(executor), abi.encode(hex"deadbeef", hex""));
        vm.stopPrank();
    }

    /// @notice Verify batch execution processes all calls (both are successful)
    function check_BatchExecutionProcessesAllCalls() external {
        Call[] memory calls = new Call[](2);
        calls[0] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.foo.selector)});
        calls[1] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.lorem.selector)});

        bytes32 mode =
            LibERC7579.encodeMode(LibERC7579.CALLTYPE_BATCH, LibERC7579.EXECTYPE_DEFAULT, bytes4(0), bytes22(0));

        vm.startPrank(address(ep));
        kernel.execute(mode, abi.encode(calls));
        vm.stopPrank();

        // Both calls should have executed
        assertEq(callee.bar(), 1);
        assertEq(callee.data(), "lorem ipsum");
    }

    /// @notice Verify that in DEFAULT mode, a reverting call in batch causes full revert
    function check_BatchDefaultModeRevertsOnFailure() external {
        Call[] memory calls = new Call[](2);
        calls[0] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.foo.selector)});
        calls[1] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.forceRevert.selector)});

        bytes32 mode =
            LibERC7579.encodeMode(LibERC7579.CALLTYPE_BATCH, LibERC7579.EXECTYPE_DEFAULT, bytes4(0), bytes22(0));

        vm.startPrank(address(ep));
        try kernel.execute(mode, abi.encode(calls)) {
            assert(false);
        } catch {}
        vm.stopPrank();

        // Since the call reverted, bar should still be 0
        assertEq(callee.bar(), 0);
    }

    /// @notice Verify that in TRY mode, a reverting call does not affect other calls
    function check_BatchTryModeSkipsFailure() external {
        Call[] memory calls = new Call[](3);
        calls[0] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.foo.selector)});
        calls[1] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.forceRevert.selector)});
        calls[2] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.lorem.selector)});

        bytes32 mode = LibERC7579.encodeMode(LibERC7579.CALLTYPE_BATCH, LibERC7579.EXECTYPE_TRY, bytes4(0), bytes22(0));

        vm.startPrank(address(ep));
        kernel.execute(mode, abi.encode(calls));
        vm.stopPrank();

        // First and third calls should have executed despite second reverting
        assertEq(callee.bar(), 1);
        assertEq(callee.data(), "lorem ipsum");
    }

    /// @notice Verify batch execution via executor works correctly
    function check_BatchExecutionViaExecutor() external {
        Call[] memory calls = new Call[](2);
        calls[0] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.foo.selector)});
        calls[1] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.lorem.selector)});

        bytes32 mode =
            LibERC7579.encodeMode(LibERC7579.CALLTYPE_BATCH, LibERC7579.EXECTYPE_DEFAULT, bytes4(0), bytes22(0));

        vm.startPrank(address(executor));
        bytes[] memory results = kernel.executeFromExecutor(mode, abi.encode(calls));
        vm.stopPrank();

        assertEq(results.length, 2);
        assertEq(callee.bar(), 1);
        assertEq(callee.data(), "lorem ipsum");
    }

    /// @notice Verify batch execution via executor in TRY mode handles reverts
    function check_BatchExecutionViaExecutorTryMode() external {
        Call[] memory calls = new Call[](3);
        calls[0] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.foo.selector)});
        calls[1] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.forceRevert.selector)});
        calls[2] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.lorem.selector)});

        bytes32 mode = LibERC7579.encodeMode(LibERC7579.CALLTYPE_BATCH, LibERC7579.EXECTYPE_TRY, bytes4(0), bytes22(0));

        vm.startPrank(address(executor));
        bytes[] memory results = kernel.executeFromExecutor(mode, abi.encode(calls));
        vm.stopPrank();

        assertEq(results.length, 3);
        assertEq(callee.bar(), 1);
        assertEq(callee.data(), "lorem ipsum");
    }

    /// @notice Verify single call in DEFAULT mode reverts properly
    function check_SingleCallDefaultRevertsOnFailure() external {
        bytes32 mode =
            LibERC7579.encodeMode(LibERC7579.CALLTYPE_SINGLE, LibERC7579.EXECTYPE_DEFAULT, bytes4(0), bytes22(0));

        vm.startPrank(address(ep));
        try kernel.execute(
            mode, abi.encodePacked(address(callee), uint256(0), abi.encodeWithSelector(MockCallee.forceRevert.selector))
        ) {
            assert(false);
        } catch {}
        vm.stopPrank();
    }

    /// @notice Verify single call in TRY mode does not revert on failure
    function check_SingleCallTryModeDoesNotRevert() external {
        bytes32 mode = LibERC7579.encodeMode(LibERC7579.CALLTYPE_SINGLE, LibERC7579.EXECTYPE_TRY, bytes4(0), bytes22(0));

        vm.startPrank(address(ep));
        kernel.execute(
            mode, abi.encodePacked(address(callee), uint256(0), abi.encodeWithSelector(MockCallee.forceRevert.selector))
        );
        vm.stopPrank();

        assertEq(callee.bar(), 0);
    }

    /// @notice Verify batch execution return data is correctly ordered
    function check_BatchReturnDataOrder() external {
        bytes memory data1 = hex"aabb";
        bytes memory data2 = hex"ccdd";

        Call[] memory calls = new Call[](2);
        calls[0] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.ret.selector, data1)});
        calls[1] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.ret.selector, data2)});

        bytes32 mode =
            LibERC7579.encodeMode(LibERC7579.CALLTYPE_BATCH, LibERC7579.EXECTYPE_DEFAULT, bytes4(0), bytes22(0));

        vm.startPrank(address(executor));
        bytes[] memory results = kernel.executeFromExecutor(mode, abi.encode(calls));
        vm.stopPrank();

        assertEq(results.length, 2);
        assertEq(keccak256(abi.decode(results[0], (bytes))), keccak256(data1));
        assertEq(keccak256(abi.decode(results[1], (bytes))), keccak256(data2));
    }
}
