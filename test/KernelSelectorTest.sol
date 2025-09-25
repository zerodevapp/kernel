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

abstract contract KernelSelectorTest is KernelTestBase {
    function test_install_selector_call() external unitTest {
        assertTrue(kernel.supportsModule(3));
        kernel.installModule(
            3,
            address(mockFallback),
            abi.encode(
                hex"deadbeef", abi.encodePacked(MockFallback.fallbackFunction.selector, bytes1(0x00), address(1))
            )
        );
        vm.expectEmit(address(mockFallback));
        emit MockFallback.Foobar();
        uint256 res = MockFallback(address(kernel)).fallbackFunction(10);
        assertEq(res, 100);
        SelectorManager.SelectorConfig memory c = kernel.selectorConfig(MockFallback.fallbackFunction.selector);
        assertEq(address(c.target), address(mockFallback));
        assertEq(address(c.hook), address(1));
        assertTrue(c.callType == CallType.wrap(bytes1(0x00)));
        assertTrue(
            kernel.isModuleInstalled(3, address(mockFallback), abi.encodePacked(MockFallback.fallbackFunction.selector))
        );
    }

    function test_install_selector_call_withhook() external unitTest {
        MockHook mockHook = new MockHook();
        kernel.installModule(4, address(mockHook), abi.encode(hex"", ""));
        kernel.installModule(
            3,
            address(mockFallback),
            abi.encode(
                hex"deadbeef", abi.encodePacked(MockFallback.fallbackFunction.selector, bytes1(0x00), address(mockHook))
            )
        );
        vm.expectEmit(address(mockFallback));
        emit MockFallback.Foobar();
        uint256 res = MockFallback(address(kernel)).fallbackFunction(10);
        assertEq(res, 100);
        SelectorManager.SelectorConfig memory c = kernel.selectorConfig(MockFallback.fallbackFunction.selector);
        assertEq(address(c.target), address(mockFallback));
        assertEq(address(c.hook), address(mockHook));
        assertTrue(c.callType == CallType.wrap(bytes1(0x00)));
    }

    function test_uninstall_selector_call() external unitTest {
        kernel.installModule(
            3,
            address(mockFallback),
            abi.encode(
                hex"deadbeef", abi.encodePacked(MockFallback.fallbackFunction.selector, bytes1(0x00), address(1))
            )
        );
        vm.expectEmit(address(mockFallback));
        emit MockFallback.Foobar();
        uint256 res = MockFallback(address(kernel)).fallbackFunction(10);
        assertEq(res, 100);
        SelectorManager.SelectorConfig memory c = kernel.selectorConfig(MockFallback.fallbackFunction.selector);
        assertEq(address(c.target), address(mockFallback));
        assertEq(address(c.hook), address(1));
        assertTrue(c.callType == CallType.wrap(bytes1(0x00)));
        kernel.uninstallModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(MockFallback.fallbackFunction.selector))
        );
        c = kernel.selectorConfig(MockFallback.fallbackFunction.selector);
        assertEq(address(c.target), address(0));
        assertEq(address(c.hook), address(0));
        assertTrue(c.callType == CallType.wrap(bytes1(0x00)));
    }

    function test_install_selector_call_fail() external unitTest {
        kernel.installModule(
            3,
            address(mockFallback),
            abi.encode(
                hex"deadbeef", abi.encodePacked(MockFallback.fallbackFunction.selector, bytes1(0x00), address(1))
            )
        );
        vm.expectRevert(MockFallback.Limit.selector, address(mockFallback));
        MockFallback(address(kernel)).fallbackFunction(100);
    }

    function test_install_selector_delegatecall() external unitTest {
        kernel.installModule(
            3,
            address(mockFallback),
            abi.encode(
                hex"deadbeef", abi.encodePacked(MockFallback.fallbackFunction.selector, bytes1(0xff), address(1))
            )
        );
        vm.expectEmit(address(kernel));
        emit MockFallback.Foobar();
        uint256 res = MockFallback(address(kernel)).fallbackFunction(10);
        assertEq(res, 100);
    }

    function test_install_selector_delegatecall_fail() external unitTest {
        kernel.installModule(
            3,
            address(mockFallback),
            abi.encode(
                hex"deadbeef", abi.encodePacked(MockFallback.fallbackFunction.selector, bytes1(0xff), address(1))
            )
        );
        vm.expectRevert(MockFallback.Limit.selector, address(kernel));
        MockFallback(address(kernel)).fallbackFunction(100);
    }

    function test_install_selector_invalid_selector() external unitTest {
        kernel.installModule(
            3,
            address(mockFallback),
            abi.encode(
                hex"deadbeef", abi.encodePacked(MockFallback.fallbackFunction.selector, bytes1(0xff), address(1))
            )
        );
        vm.expectRevert(InvalidSelector.selector, address(kernel));
        MockFallback(address(kernel)).getData();
    }
}
