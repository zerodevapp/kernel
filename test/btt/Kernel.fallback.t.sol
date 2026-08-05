// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {BTTModifiers} from "./BTTModifiers.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/interfaces/IERC721Receiver.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/interfaces/IERC1155Receiver.sol";
import {InvalidSelector, InvalidCallType} from "src/types/Error.sol";
import {CALLTYPE_SINGLE, CALLTYPE_DELEGATECALL} from "src/types/Constants.sol";
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
        vm.prank(address(ep));
        kernel.installModule(
            3,
            address(mockFallback),
            abi.encode(hex"", abi.encodePacked(MockFallback.testFunction.selector, CALLTYPE_SINGLE))
        );

        assertEq(MockFallback(address(kernel)).testFunction(), 42);
    }

    function test_WhenDelegatecallFallbackIsInstalled() external {
        vm.prank(address(ep));
        kernel.installModule(
            3,
            address(mockFallback),
            abi.encode(hex"", abi.encodePacked(MockFallback.fallbackFunction.selector, CALLTYPE_DELEGATECALL))
        );

        assertEq(MockFallback(address(kernel)).fallbackFunction(5), 25);
    }

    function test_WhenFallbackCallTypeIsInvalid() external {
        vm.prank(address(ep));
        kernel.installModule(
            3,
            address(mockFallback),
            abi.encode(hex"", abi.encodePacked(MockFallback.testFunction.selector, bytes1(0x02)))
        );

        vm.expectRevert(InvalidCallType.selector);
        MockFallback(address(kernel)).testFunction();
    }
}
