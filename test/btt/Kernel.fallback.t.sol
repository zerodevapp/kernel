// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {BTTModifiers} from "./BTTModifiers.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/interfaces/IERC721Receiver.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/interfaces/IERC1155Receiver.sol";
import {InvalidSelector, InvalidCallType} from "src/types/Error.sol";
import {CALLTYPE_SINGLE, CALLTYPE_DELEGATECALL, SCOPED_EXECUTION_HOOK_SELECTOR_SCOPE} from "src/types/Constants.sol";
import {MockFallback} from "../mock/MockFallback.sol";

/// @notice Fallback routing tests after removal of generic fallback hooks.
abstract contract Kernel_fallback is BTTModifiers {
    function test_WhenTheSelectorIsOnERC721Received() external {
        bytes4 selector = IERC721Receiver.onERC721Received.selector;
        (bool success, bytes memory result) =
            address(kernel).call(abi.encodeWithSelector(selector, address(this), address(this), 1, ""));
        assertTrue(success, "Call should succeed");
        assertEq(abi.decode(result, (bytes4)), selector, "Should return magic value");
    }

    function test_WhenTheSelectorIsOnERC1155Received() external {
        bytes4 selector = IERC1155Receiver.onERC1155Received.selector;
        (bool success, bytes memory result) =
            address(kernel).call(abi.encodeWithSelector(selector, address(this), address(this), 1, 1, ""));
        assertTrue(success, "Call should succeed");
        assertEq(abi.decode(result, (bytes4)), selector, "Should return magic value");
    }

    function test_WhenTheSelectorIsOnERC1155BatchReceived() external {
        bytes4 selector = IERC1155Receiver.onERC1155BatchReceived.selector;
        uint256[] memory ids = new uint256[](1);
        uint256[] memory amounts = new uint256[](1);
        (bool success, bytes memory result) =
            address(kernel).call(abi.encodeWithSelector(selector, address(this), address(this), ids, amounts, ""));
        assertTrue(success, "Call should succeed");
        assertEq(abi.decode(result, (bytes4)), selector, "Should return magic value");
    }

    function test_GivenTheSelectorIsNotRegistered() external {
        bytes4 unregisteredSelector = bytes4(keccak256("unregistered()"));
        vm.expectRevert(InvalidSelector.selector);
        (bool success,) = address(kernel).call(abi.encodeWithSelector(unregisteredSelector));
        success;
    }

    function test_WhenSingleCallFallbackIsInstalled() external {
        vm.startPrank(address(ep));
        kernel.installModule(
            3,
            address(mockFallback),
            abi.encode(hex"", abi.encodePacked(MockFallback.testFunction.selector, CALLTYPE_SINGLE))
        );
        // Selectors without a scoped execution hook are EntryPoint-only; install a
        // passthrough scoped hook so the selector is publicly callable.
        kernel.installModule(
            11,
            address(hook),
            abi.encode(
                hex"", abi.encodePacked(SCOPED_EXECUTION_HOOK_SELECTOR_SCOPE, MockFallback.testFunction.selector)
            )
        );
        vm.stopPrank();

        // testFunction() is view, so use a raw call (non-static) to let the
        // scoped hook run pre/post checks.
        (bool success, bytes memory ret) = address(kernel).call(abi.encodePacked(MockFallback.testFunction.selector));
        assertTrue(success);
        assertEq(abi.decode(ret, (uint256)), 42);
    }

    function test_WhenDelegatecallFallbackIsInstalled() external {
        vm.startPrank(address(ep));
        kernel.installModule(
            3,
            address(mockFallback),
            abi.encode(hex"", abi.encodePacked(MockFallback.fallbackFunction.selector, CALLTYPE_DELEGATECALL))
        );
        kernel.installModule(
            11,
            address(hook),
            abi.encode(
                hex"", abi.encodePacked(SCOPED_EXECUTION_HOOK_SELECTOR_SCOPE, MockFallback.fallbackFunction.selector)
            )
        );
        vm.stopPrank();

        assertEq(MockFallback(address(kernel)).fallbackFunction(5), 25);
    }

    function test_WhenFallbackCallTypeIsInvalid() external {
        vm.startPrank(address(ep));
        kernel.installModule(
            3,
            address(mockFallback),
            abi.encode(hex"", abi.encodePacked(MockFallback.testFunction.selector, bytes1(0x02)))
        );
        // A scoped hook bypasses the EntryPoint-only gate so the call reaches the
        // invalid-callType check.
        kernel.installModule(
            11,
            address(hook),
            abi.encode(
                hex"", abi.encodePacked(SCOPED_EXECUTION_HOOK_SELECTOR_SCOPE, MockFallback.testFunction.selector)
            )
        );
        vm.stopPrank();

        vm.expectRevert(InvalidCallType.selector);
        address(kernel).call(abi.encodePacked(MockFallback.testFunction.selector));
    }
}
