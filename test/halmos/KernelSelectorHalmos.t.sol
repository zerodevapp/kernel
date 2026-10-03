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

contract KernelSelectorHalmos is SymTest, Test {
    Kernel private kernel;
    IEntryPoint private ep;
    MockFallback private fallbackModule;

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
    }

    function checkSelectorInstallUninstall() external {
        bytes4 selector = bytes4(svm.createBytes(4, "selector"));
        bytes1 callType = CallType.unwrap(CALLTYPE_SINGLE);
        bytes memory internalData = abi.encodePacked(selector, callType);

        vm.startPrank(address(ep));
        kernel.installModule(3, address(fallbackModule), abi.encode(hex"deadbeef", internalData));
        vm.stopPrank();

        assertTrue(kernel.isModuleInstalled(3, address(fallbackModule), abi.encodePacked(selector)));
        SelectorConfig memory cfg = kernel.selectorConfig(selector);
        assertEq(cfg.target, address(fallbackModule));
        assertEq(CallType.unwrap(cfg.callType), callType);

        vm.startPrank(address(ep));
        kernel.uninstallModule(3, address(fallbackModule), abi.encode(hex"", abi.encodePacked(selector)));
        vm.stopPrank();

        assertFalse(kernel.isModuleInstalled(3, address(fallbackModule), abi.encodePacked(selector)));
        cfg = kernel.selectorConfig(selector);
        assertEq(cfg.target, address(0));
        assertEq(CallType.unwrap(cfg.callType), bytes1(0));
    }

    function checkSelectorCallTypeAppendsSender() external {
        bytes1 callType = CallType.unwrap(CALLTYPE_SINGLE);
        bytes memory internalData = abi.encodePacked(MockFallback.getCaller.selector, callType);
        vm.startPrank(address(ep));
        kernel.installModule(3, address(fallbackModule), abi.encode(hex"deadbeef", internalData));
        vm.stopPrank();

        address caller = address(0xBEEF);
        bytes20 payload = bytes20(address(0x1111111111111111111111111111111111111111));
        bytes memory data = abi.encodePacked(MockFallback.getCaller.selector, payload);
        vm.startPrank(caller);
        (bool success, bytes memory ret) = address(kernel).call(data);
        vm.stopPrank();
        assertTrue(success);
        address decoded = abi.decode(ret, (address));
        assertEq(decoded, caller);
    }

    function checkSelectorDelegatecallDoesNotAppendSender() external {
        bytes1 callType = bytes1(uint8(0xFF));
        bytes memory internalData = abi.encodePacked(MockFallback.getCaller.selector, callType);
        vm.startPrank(address(ep));
        kernel.installModule(3, address(fallbackModule), abi.encode(hex"deadbeef", internalData));
        vm.stopPrank();

        address caller = address(0xBEEF);
        address payloadAddr = address(0x1111111111111111111111111111111111111111);
        bytes memory data = abi.encodePacked(MockFallback.getCaller.selector, bytes20(payloadAddr));
        vm.startPrank(caller);
        (bool success, bytes memory ret) = address(kernel).call(data);
        vm.stopPrank();
        assertTrue(success);
        address decoded = abi.decode(ret, (address));
        assertEq(decoded, payloadAddr);
    }
}
