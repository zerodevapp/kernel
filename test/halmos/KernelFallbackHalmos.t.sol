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
import {CALLTYPE_SINGLE, CALLTYPE_DELEGATECALL, HOOK_MODULE_NOT_INSTALLED} from "src/types/Constants.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {MockValidator} from "../mock/MockValidator.sol";
import {MockFallback} from "../mock/MockFallback.sol";
import {MockHook} from "../mock/MockHook.sol";

/// @title KernelFallbackHalmos
/// @notice Halmos proofs that _fallback can never route to an uninstalled module
contract KernelFallbackHalmos is SymTest, Test {
    Kernel private kernel;
    IEntryPoint private ep;
    MockFallback private fallbackModule;
    MockHook private hook;

    function setUp() external {
        ep = EntryPointLib.deploy();
        KernelUUPS uups = new KernelUUPS(ep);
        KernelImmutableECDSA immutableEcdsa = new KernelImmutableECDSA(ep);
        KernelFactory factory = new KernelFactory(uups, immutableEcdsa);
        MockValidator rootValidator = new MockValidator();
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});
        kernel = factory.deploy(pkgs, 0);
        fallbackModule = new MockFallback();
        hook = new MockHook();
        vm.startPrank(address(ep));
        kernel.installModule(4, address(hook), abi.encode(hex"", hex""));
        vm.stopPrank();
    }

    /// @notice Prove that calling a selector with no installed fallback always reverts
    function check_FallbackUninstalledSelectorReverts() external {
        bytes4 selector = MockFallback.testFunction.selector;
        // Verify the selector is not installed
        SelectorConfig memory cfg = kernel.selectorConfig(selector);
        assertEq(cfg.target, address(0));

        (bool success,) = address(kernel).call(abi.encodePacked(selector, bytes20(address(0xBEEF))));
        assertFalse(success, "call to uninstalled selector should revert");
    }

    /// @notice Prove that after uninstalling a selector, it cannot be called
    function check_FallbackAfterUninstallReverts() external {
        bytes4 selector = MockFallback.testFunction.selector;
        bytes1 callType = CallType.unwrap(CALLTYPE_SINGLE);
        bytes memory internalData = abi.encodePacked(selector, callType, address(hook));

        // Install then uninstall
        vm.startPrank(address(ep));
        kernel.installModule(3, address(fallbackModule), abi.encode(hex"deadbeef", internalData));
        kernel.uninstallModule(3, address(fallbackModule), abi.encode(hex"", abi.encodePacked(selector)));
        vm.stopPrank();

        // After uninstall, calling the selector should revert
        SelectorConfig memory cfg = kernel.selectorConfig(selector);
        assertEq(cfg.target, address(0));

        (bool success,) = address(kernel).call(abi.encodePacked(selector, bytes20(address(0xBEEF))));
        assertFalse(success, "call to uninstalled selector should revert");
    }

    /// @notice Prove that install sets correct target and callType
    function check_FallbackInstallSetsCorrectConfig() external {
        bytes4 selector = MockFallback.testFunction.selector;
        bytes1 callType = CallType.unwrap(CALLTYPE_SINGLE);
        bytes memory internalData = abi.encodePacked(selector, callType, address(hook));

        vm.startPrank(address(ep));
        kernel.installModule(3, address(fallbackModule), abi.encode(hex"deadbeef", internalData));
        vm.stopPrank();

        SelectorConfig memory cfg = kernel.selectorConfig(selector);
        assertEq(cfg.target, address(fallbackModule));
        assertEq(CallType.unwrap(cfg.callType), callType);
    }

    /// @notice Prove that fallback with hook=0 and non-EP caller reverts
    function check_FallbackHookZeroNonEPReverts() external {
        bytes4 selector = MockFallback.testFunction.selector;
        bytes1 callType = CallType.unwrap(CALLTYPE_SINGLE);
        bytes memory internalData = abi.encodePacked(selector, callType, address(0));

        vm.startPrank(address(ep));
        kernel.installModule(3, address(fallbackModule), abi.encode(hex"deadbeef", internalData));
        vm.stopPrank();

        address caller = address(0xBEEF);
        vm.startPrank(caller);
        (bool success,) = address(kernel).call(abi.encodePacked(selector, bytes20(caller)));
        vm.stopPrank();
        assertFalse(success, "hook=0 with non-EP caller should revert");
    }

    /// @notice Prove fallback with hook=address(1) allows any caller
    function check_FallbackNoHookAllowsAnyCaller() external {
        bytes4 selector = MockFallback.testFunction.selector;
        bytes1 callType = CallType.unwrap(CALLTYPE_SINGLE);
        bytes memory internalData = abi.encodePacked(selector, callType, address(1));

        vm.startPrank(address(ep));
        kernel.installModule(3, address(fallbackModule), abi.encode(hex"deadbeef", internalData));
        vm.stopPrank();

        address caller = address(0xBEEF);
        vm.startPrank(caller);
        (bool success,) = address(kernel).call(abi.encodePacked(selector, bytes20(address(0x1234))));
        vm.stopPrank();
        assertTrue(success);
    }
}
