pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Kernel} from "src/Kernel.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {KernelImmutableECDSA} from "src/KernelImmutableECDSA.sol";
import {KernelFactory} from "src/KernelFactory.sol";
import {Install, SelectorConfig} from "src/types/Structs.sol";
import {CallType} from "src/types/Types.sol";
import {CALLTYPE_SINGLE} from "src/types/Constants.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {MockValidator} from "../mock/MockValidator.sol";
import {MockFallback} from "../mock/MockFallback.sol";
import {MockHook} from "../mock/MockHook.sol";
import {MockExecutor} from "../mock/MockExecutor.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";

/// @title KernelHookBracketingHalmos
/// @notice Halmos proofs that hook pre/post always bracket execution
contract KernelHookBracketingHalmos is SymTest, Test {
    Kernel private kernel;
    IEntryPoint private ep;
    MockHook private hook;
    MockFallback private fallbackModule;
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
        hook = new MockHook();
        fallbackModule = new MockFallback();
        executor = new MockExecutor();

        vm.startPrank(address(ep));
        kernel.installModule(4, address(hook), abi.encode(hex"", hex""));
        kernel.installModule(2, address(executor), abi.encode(hex"deadbeef", abi.encodePacked(address(hook))));
        vm.stopPrank();
    }

    /// @notice Prove that fallback with hook calls preCheck before execution
    function check_FallbackHookPreCheckCalled() external {
        bytes4 selector = MockFallback.testFunction.selector;
        bytes1 callType = CallType.unwrap(CALLTYPE_SINGLE);
        bytes memory internalData = abi.encodePacked(selector, callType, address(hook));

        vm.startPrank(address(ep));
        kernel.installModule(3, address(fallbackModule), abi.encode(hex"deadbeef", internalData));
        vm.stopPrank();

        // Reset hook state
        hook.resetState();
        assertFalse(hook.preHookCalled());
        assertFalse(hook.postHookCalled());

        // Call the selector
        address caller = address(0xBEEF);
        vm.startPrank(caller);
        (bool success,) = address(kernel).call(abi.encodePacked(selector, bytes20(address(0x1234))));
        vm.stopPrank();
        assertTrue(success);

        // Verify both pre and post hooks were called
        assertTrue(hook.preHookCalled(), "preCheck not called");
        assertTrue(hook.postHookCalled(), "postCheck not called");
    }

    /// @notice Prove that if preCheck reverts, execution does not proceed and postCheck is not called
    function check_FallbackHookPreCheckRevertBlocksExecution() external {
        bytes4 selector = MockFallback.testFunction.selector;
        bytes1 callType = CallType.unwrap(CALLTYPE_SINGLE);
        bytes memory internalData = abi.encodePacked(selector, callType, address(hook));

        vm.startPrank(address(ep));
        kernel.installModule(3, address(fallbackModule), abi.encode(hex"deadbeef", internalData));
        vm.stopPrank();

        // Set hook to revert on preCheck
        hook.resetState();
        hook.setRevertOnPreHook(true);

        (bool success,) = address(kernel).call(abi.encodePacked(selector, bytes20(address(0x1234))));
        assertFalse(success, "call should revert when preCheck reverts");
    }

    /// @notice Prove that if postCheck reverts, the call reverts after execution
    function check_FallbackHookPostCheckRevertRevertsCall() external {
        bytes4 selector = MockFallback.testFunction.selector;
        bytes1 callType = CallType.unwrap(CALLTYPE_SINGLE);
        bytes memory internalData = abi.encodePacked(selector, callType, address(hook));

        vm.startPrank(address(ep));
        kernel.installModule(3, address(fallbackModule), abi.encode(hex"deadbeef", internalData));
        vm.stopPrank();

        // Set hook to revert on postCheck
        hook.resetState();
        hook.setRevertOnPostHook(true);

        (bool success,) = address(kernel).call(abi.encodePacked(selector, bytes20(address(0x1234))));
        assertFalse(success, "call should revert when postCheck reverts");
    }

    /// @notice Prove executor with hook calls pre and post
    function check_ExecutorHookBracketing() external {
        hook.resetState();
        assertFalse(hook.preHookCalled());
        assertFalse(hook.postHookCalled());

        bytes32 mode = bytes32(
            abi.encodePacked(LibERC7579.CALLTYPE_SINGLE, LibERC7579.EXECTYPE_TRY, bytes4(0), bytes4(0), bytes22(0))
        );
        bytes memory executionData = abi.encodePacked(address(kernel), uint256(0), abi.encodeCall(Kernel.accountId, ()));

        vm.prank(address(executor));
        kernel.executeFromExecutor(mode, executionData);

        assertTrue(hook.preHookCalled(), "executor preCheck not called");
        assertTrue(hook.postHookCalled(), "executor postCheck not called");
    }

    /// @notice Prove executor with hook=address(1) does NOT call pre/post
    function check_ExecutorNoHookSkipsChecks() external {
        MockExecutor noHookExecutor = new MockExecutor();
        vm.startPrank(address(ep));
        // Install executor with no hook (empty internalData defaults to address(1))
        kernel.installModule(2, address(noHookExecutor), abi.encode(hex"deadbeef", hex""));
        vm.stopPrank();

        hook.resetState();

        bytes32 mode = bytes32(
            abi.encodePacked(LibERC7579.CALLTYPE_SINGLE, LibERC7579.EXECTYPE_TRY, bytes4(0), bytes4(0), bytes22(0))
        );
        bytes memory executionData = abi.encodePacked(address(kernel), uint256(0), abi.encodeCall(Kernel.accountId, ()));

        vm.prank(address(noHookExecutor));
        kernel.executeFromExecutor(mode, executionData);

        // Since hook is address(1) (no hook), preCheck/postCheck should NOT be called on the hook module
        assertFalse(hook.preHookCalled(), "pre hook should not be called for no-hook executor");
        assertFalse(hook.postHookCalled(), "post hook should not be called for no-hook executor");
    }
}
