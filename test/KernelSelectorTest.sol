pragma solidity ^0.8.0;

import {MockFallback} from "./mock/MockFallback.sol";
import {Kernel} from "src/Kernel.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import {CallType} from "src/types/Types.sol";
import {KernelTestBase} from "./KernelTestBase.sol";
import {InvalidSelector, InvalidDataLength, ScopedExecutionHookStillInstalled} from "src/types/Error.sol";
import {SCOPED_EXECUTION_HOOK_SELECTOR_SCOPE} from "src/types/Constants.sol";
import {
    selectorScopedExecutionHookId,
    getScopedExecutionHookScope,
    getScopedExecutionHookSelector
} from "src/lib/Utils.sol";
import {SelectorConfig} from "src/types/Structs.sol";

abstract contract KernelSelectorTest is KernelTestBase {
    function test_install_selector_call() external unitTest {
        address newCaller = makeAddr("Caller");
        assertTrue(kernel.supportsModule(3));
        kernel.installModule(
            3,
            address(mockFallback),
            abi.encode(hex"deadbeef", abi.encodePacked(MockFallback.fallbackFunction.selector, bytes1(0x00)))
        );
        // Selectors without a scoped execution hook are EntryPoint-only; install a
        // passthrough scoped hook so the selector can be called by arbitrary callers.
        kernel.installModule(
            11,
            address(hook),
            abi.encode(
                hex"deadbeef",
                abi.encodePacked(SCOPED_EXECUTION_HOOK_SELECTOR_SCOPE, MockFallback.fallbackFunction.selector)
            )
        );
        vm.stopPrank();
        vm.startPrank(newCaller);
        vm.expectEmit(address(mockFallback));
        emit MockFallback.Foobar();
        uint256 res = MockFallback(address(kernel)).fallbackFunction(10);
        address caller = mockFallback.caller();
        assertEq(res, 100);
        assertEq(caller, newCaller);
        SelectorConfig memory c = kernel.selectorConfig(MockFallback.fallbackFunction.selector);
        assertEq(address(c.target), address(mockFallback));
        assertTrue(c.callType == CallType.wrap(bytes1(0x00)));
        assertTrue(
            kernel.isModuleInstalled(3, address(mockFallback), abi.encodePacked(MockFallback.fallbackFunction.selector))
        );
    }

    function test_install_selector_without_hook_is_entrypoint_only() external unitTest {
        bytes4 selector = MockFallback.fallbackFunction.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"deadbeef", abi.encodePacked(selector, bytes1(0x00)))
        );
        vm.stopPrank();

        // Selectors without a scoped execution hook are only callable by the EntryPoint.
        address newCaller = makeAddr("Caller");
        vm.startPrank(newCaller);
        vm.expectRevert(InvalidSelector.selector);
        MockFallback(address(kernel)).fallbackFunction(10);
        vm.stopPrank();

        vm.startPrank(address(ep));
        uint256 res = MockFallback(address(kernel)).fallbackFunction(10);
        assertEq(res, 100);
        vm.stopPrank();
    }

    function test_selector_scoped_execution_hook() external unitTest {
        bytes4 selector = MockFallback.fallbackFunction.selector;
        bytes memory hookContext = abi.encodePacked(SCOPED_EXECUTION_HOOK_SELECTOR_SCOPE, selector);
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"deadbeef", abi.encodePacked(selector, bytes1(0x00)))
        );
        kernel.installModule(11, address(hook), abi.encode(hex"deadbeef", hookContext));

        uint256 res = MockFallback(address(kernel)).fallbackFunction(10);
        bytes32 expectedId = selectorScopedExecutionHookId(selector);
        assertEq(getScopedExecutionHookScope(expectedId), SCOPED_EXECUTION_HOOK_SELECTOR_SCOPE);
        assertEq(getScopedExecutionHookSelector(expectedId), selector);
        assertEq(res, 100);
        assertEq(hook.preCheckId(address(kernel)), expectedId);
        assertEq(hook.postCheckId(address(kernel)), expectedId);
        assertTrue(kernel.isModuleInstalled(11, address(hook), hookContext));
        assertEq(address(kernel.selectorConfig(selector).scopedExecutionHook), address(hook));

        vm.expectRevert(ScopedExecutionHookStillInstalled.selector);
        kernel.uninstallModule(3, address(mockFallback), abi.encode(hex"", abi.encodePacked(selector)));
        kernel.uninstallModule(11, address(hook), abi.encode(hex"", hookContext));
        kernel.uninstallModule(3, address(mockFallback), abi.encode(hex"", abi.encodePacked(selector)));
        assertEq(kernel.selectorConfig(selector).target, address(0));
    }

    function test_uninstall_selector_call() external unitTest {
        kernel.installModule(
            3,
            address(mockFallback),
            abi.encode(hex"deadbeef", abi.encodePacked(MockFallback.fallbackFunction.selector, bytes1(0x00)))
        );
        vm.expectEmit(address(mockFallback));
        emit MockFallback.Foobar();
        uint256 res = MockFallback(address(kernel)).fallbackFunction(10);
        assertEq(res, 100);
        SelectorConfig memory c = kernel.selectorConfig(MockFallback.fallbackFunction.selector);
        assertEq(address(c.target), address(mockFallback));
        assertTrue(c.callType == CallType.wrap(bytes1(0x00)));
        kernel.uninstallModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(MockFallback.fallbackFunction.selector))
        );
        c = kernel.selectorConfig(MockFallback.fallbackFunction.selector);
        assertEq(address(c.target), address(0));
        assertTrue(c.callType == CallType.wrap(bytes1(0x00)));
    }

    function test_install_selector_call_fail() external unitTest {
        kernel.installModule(
            3,
            address(mockFallback),
            abi.encode(hex"deadbeef", abi.encodePacked(MockFallback.fallbackFunction.selector, bytes1(0x00)))
        );
        vm.expectRevert(MockFallback.Limit.selector, address(mockFallback));
        MockFallback(address(kernel)).fallbackFunction(100);
    }

    function test_install_selector_delegatecall() external unitTest {
        kernel.installModule(
            3,
            address(mockFallback),
            abi.encode(hex"deadbeef", abi.encodePacked(MockFallback.fallbackFunction.selector, bytes1(0xff)))
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
            abi.encode(hex"deadbeef", abi.encodePacked(MockFallback.fallbackFunction.selector, bytes1(0xff)))
        );
        vm.expectRevert(MockFallback.Limit.selector, address(kernel));
        MockFallback(address(kernel)).fallbackFunction(100);
    }

    function test_install_selector_rejects_trailing_legacy_hook_data() external unitTest {
        vm.expectRevert(InvalidDataLength.selector);
        kernel.installModule(
            3,
            address(mockFallback),
            abi.encode(hex"", abi.encodePacked(MockFallback.fallbackFunction.selector, bytes1(0x00), address(1)))
        );
    }

    function test_install_selector_native_routes_take_precedence() external unitTest {
        bytes4[4] memory selectors = [
            Kernel.supportsModule.selector,
            IERC721Receiver.onERC721Received.selector,
            IERC1155Receiver.onERC1155Received.selector,
            IERC1155Receiver.onERC1155BatchReceived.selector
        ];
        for (uint256 i; i < selectors.length; i++) {
            kernel.installModule(
                3, address(mockFallback), abi.encode(hex"deadbeef", abi.encodePacked(selectors[i], bytes1(0x00)))
            );
            assertEq(kernel.selectorConfig(selectors[i]).target, address(mockFallback));
        }

        bytes memory hookContext =
            abi.encodePacked(SCOPED_EXECUTION_HOOK_SELECTOR_SCOPE, IERC721Receiver.onERC721Received.selector);
        kernel.installModule(11, address(hook), abi.encode(hex"deadbeef", hookContext));

        assertTrue(kernel.supportsModule(3));
        bytes4 result = IERC721Receiver(address(kernel)).onERC721Received(address(this), address(this), 1, "");
        assertEq(result, IERC721Receiver.onERC721Received.selector);
        assertEq(hook.preCheckId(address(kernel)), bytes32(0));
        assertEq(hook.postCheckId(address(kernel)), bytes32(0));
    }

    function test_install_selector_invalid_selector() external unitTest {
        kernel.installModule(
            3,
            address(mockFallback),
            abi.encode(hex"deadbeef", abi.encodePacked(MockFallback.fallbackFunction.selector, bytes1(0xff)))
        );
        vm.expectRevert(InvalidSelector.selector, address(kernel));
        MockFallback(address(kernel)).getData();
    }
}
