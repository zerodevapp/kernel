// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {BTTModifiers} from "./BTTModifiers.sol";
import {Kernel} from "src/Kernel.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/interfaces/IERC721Receiver.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/interfaces/IERC1155Receiver.sol";
import {InvalidSelector, InvalidCallType} from "src/types/Error.sol";
import {MockFallback} from "../mock/MockFallback.sol";
import {MockHook} from "../mock/MockHook.sol";

abstract contract Kernel_fallback is BTTModifiers {
    bool internal _customSelector;
    address internal _hookAddress;
    bytes1 internal _callType;
    bool internal _preHookSucceeds;
    bool internal _targetCallSucceeds;

    function test_WhenTheSelectorIsOnERC721Received() external {
        // it should return the selector as magic value
        bytes4 selector = IERC721Receiver.onERC721Received.selector;
        (bool success, bytes memory result) =
            address(kernel).call(abi.encodeWithSelector(selector, address(this), address(this), 1, ""));
        assertTrue(success, "Call should succeed");
        assertEq(abi.decode(result, (bytes4)), selector, "Should return magic value");
    }

    function test_WhenTheSelectorIsOnERC1155Received() external {
        // it should return the selector as magic value
        bytes4 selector = IERC1155Receiver.onERC1155Received.selector;
        (bool success, bytes memory result) =
            address(kernel).call(abi.encodeWithSelector(selector, address(this), address(this), 1, 1, ""));
        assertTrue(success, "Call should succeed");
        assertEq(abi.decode(result, (bytes4)), selector, "Should return magic value");
    }

    function test_WhenTheSelectorIsOnERC1155BatchReceived() external {
        // it should return the selector as magic value
        bytes4 selector = IERC1155Receiver.onERC1155BatchReceived.selector;
        uint256[] memory ids = new uint256[](1);
        uint256[] memory amounts = new uint256[](1);
        (bool success, bytes memory result) =
            address(kernel).call(abi.encodeWithSelector(selector, address(this), address(this), ids, amounts, ""));
        assertTrue(success, "Call should succeed");
        assertEq(abi.decode(result, (bytes4)), selector, "Should return magic value");
    }

    modifier whenTheSelectorIsACustomRegisteredSelector() {
        _customSelector = true;
        _;
    }

    function test_GivenTheSelectorIsNotRegistered() external whenTheSelectorIsACustomRegisteredSelector {
        // it should revert with InvalidSelector error
        bytes4 unregisteredSelector = bytes4(keccak256("unregistered()"));
        vm.expectRevert(InvalidSelector.selector);
        (bool success,) = address(kernel).call(abi.encodeWithSelector(unregisteredSelector));
        // expectRevert handles the revert check
    }

    /*//////////////////////////////////////////////////////////////
                    HOOK = ADDRESS(0) BRANCH
    //////////////////////////////////////////////////////////////*/

    modifier givenTheSelectorIsRegisteredButHookIsAddress0() {
        _hookAddress = address(0);
        _;
    }

    function test_WhenTheCallerIsNotTheEntryPoint()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredButHookIsAddress0
    {
        // it should revert with InvalidSelector error
        vm.stopPrank();
        vm.startPrank(address(ep));

        // Register fallback with hook=address(0)
        bytes4 testSelector = MockFallback.getData.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, _callType, _hookAddress))
        );
        vm.stopPrank();

        // Call from non-EntryPoint
        address randomCaller = makeAddr("randomCaller");
        vm.startPrank(randomCaller);
        vm.expectRevert(InvalidSelector.selector);
        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
    }

    modifier whenTheCallerIsTheEntryPoint() {
        vm.stopPrank();
        vm.startPrank(address(ep));
        _;
    }

    modifier givenCallTypeIsCALL() {
        _callType = bytes1(0x00);
        _;
    }

    function test_GivenCallTypeIsCALL()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredButHookIsAddress0
        whenTheCallerIsTheEntryPoint
        givenCallTypeIsCALL
    {
        // it should call the target with msgdata plus msgsender
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.getCaller.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, _callType, _hookAddress))
        );

        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
        assertTrue(success, "Call should succeed");
    }

    function test_WhenTheTargetCallSucceeds()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredButHookIsAddress0
        whenTheCallerIsTheEntryPoint
        givenCallTypeIsCALL
    {
        // it should return the call result
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.getCaller.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, _callType, _hookAddress))
        );

        (bool success, bytes memory result) = address(kernel).call(abi.encodeWithSelector(testSelector));
        assertTrue(success, "Call should succeed and return result");
    }

    function test_WhenTheTargetCallReverts()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredButHookIsAddress0
        whenTheCallerIsTheEntryPoint
        givenCallTypeIsCALL
    {
        // it should propagate the revert
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.forceRevert.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, _callType, _hookAddress))
        );

        vm.expectRevert(MockFallback.FallbackRevert.selector);
        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
    }

    modifier givenCallTypeIsDELEGATECALL() {
        _callType = bytes1(0xff);
        _;
    }

    function test_GivenCallTypeIsDELEGATECALL()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredButHookIsAddress0
        whenTheCallerIsTheEntryPoint
        givenCallTypeIsDELEGATECALL
    {
        // it should delegatecall the target with msgdata
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.testFunction.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, _callType, _hookAddress))
        );

        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
        assertTrue(success, "Delegatecall should succeed");
    }

    function test_WhenTheDelegatecallSucceeds()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredButHookIsAddress0
        whenTheCallerIsTheEntryPoint
        givenCallTypeIsDELEGATECALL
    {
        // it should return the delegatecall result
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.testFunction.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, _callType, _hookAddress))
        );

        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
        assertTrue(success, "Delegatecall should return result");
    }

    function test_WhenTheDelegatecallReverts()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredButHookIsAddress0
        whenTheCallerIsTheEntryPoint
        givenCallTypeIsDELEGATECALL
    {
        // it should propagate the revert
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.forceRevert.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, _callType, _hookAddress))
        );

        vm.expectRevert(MockFallback.FallbackRevert.selector);
        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
    }

    function test_GivenCallTypeIsUnsupported()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredButHookIsAddress0
        whenTheCallerIsTheEntryPoint
    {
        // it should revert with InvalidCallType error
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.getCaller.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, bytes1(0x02), address(0)))
        );

        vm.expectRevert(InvalidCallType.selector);
        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
    }

    /*//////////////////////////////////////////////////////////////
                    HOOK = ADDRESS(1) BRANCH
    //////////////////////////////////////////////////////////////*/

    modifier givenTheSelectorIsRegisteredWithHookSetToAddress1() {
        _hookAddress = address(1);
        _;
    }

    function test_GivenTheSelectorIsRegisteredWithHookSetToAddress1()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredWithHookSetToAddress1
    {
        // it should skip preHook and postHook
        // it should allow any caller
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.getCaller.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, _callType, _hookAddress))
        );
        vm.stopPrank();

        // Call from any address should work
        address anyCaller = makeAddr("anyCaller");
        vm.startPrank(anyCaller);
        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
        assertTrue(success, "Any caller should succeed with hook=address(1)");
    }

    function test_GivenCallTypeIsCALL_GivenCallTypeIsCALL()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredWithHookSetToAddress1
        givenCallTypeIsCALL
    {
        // it should call the target with msgdata plus msgsender
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.getCaller.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, _callType, _hookAddress))
        );

        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
        assertTrue(success, "Should call target with CALL type");
    }

    function test_WhenTheTargetCallSucceeds_GivenCallTypeIsCALL()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredWithHookSetToAddress1
        givenCallTypeIsCALL
    {
        // it should return the call result
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.getCaller.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, _callType, _hookAddress))
        );

        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
        assertTrue(success, "Should return call result on success");
    }

    function test_WhenTheTargetCallReverts_GivenCallTypeIsCALL()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredWithHookSetToAddress1
        givenCallTypeIsCALL
    {
        // it should propagate the revert
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.forceRevert.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, _callType, _hookAddress))
        );

        vm.expectRevert(MockFallback.FallbackRevert.selector);
        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
    }

    function test_GivenCallTypeIsDELEGATECALL_GivenCallTypeIsDELEGATECALL()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredWithHookSetToAddress1
        givenCallTypeIsDELEGATECALL
    {
        // it should delegatecall the target with msgdata
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.testFunction.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, _callType, _hookAddress))
        );

        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
        assertTrue(success, "Should delegatecall target");
    }

    function test_WhenTheDelegatecallSucceeds_GivenCallTypeIsDELEGATECALL()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredWithHookSetToAddress1
        givenCallTypeIsDELEGATECALL
    {
        // it should return the delegatecall result
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.testFunction.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, _callType, _hookAddress))
        );

        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
        assertTrue(success, "Should return delegatecall result");
    }

    function test_WhenTheDelegatecallReverts_GivenCallTypeIsDELEGATECALL()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredWithHookSetToAddress1
        givenCallTypeIsDELEGATECALL
    {
        // it should propagate the revert
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.forceRevert.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, _callType, _hookAddress))
        );

        vm.expectRevert(MockFallback.FallbackRevert.selector);
        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
    }

    function test_GivenCallTypeIsUnsupported_GivenTheSelectorIsRegisteredWithHookSetToAddress1()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredWithHookSetToAddress1
    {
        // it should revert with InvalidCallType error
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.testFunction.selector;
        // Using 0x02 as unsupported call type
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, bytes1(0x02), address(1)))
        );

        vm.expectRevert(InvalidCallType.selector);
        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
    }

    function test_GivenCallTypeIsCALL_Hook1()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredWithHookSetToAddress1
        givenCallTypeIsCALL
    {
        // it should call the target with msgdata plus msgsender
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.getCaller.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, _callType, _hookAddress))
        );

        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
        assertTrue(success, "Call should succeed");
    }

    function test_WhenTheTargetCallSucceeds_Hook1()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredWithHookSetToAddress1
        givenCallTypeIsCALL
    {
        // it should return the call result
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.getCaller.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, _callType, _hookAddress))
        );

        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
        assertTrue(success, "Should return call result");
    }

    function test_WhenTheTargetCallReverts_Hook1()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredWithHookSetToAddress1
        givenCallTypeIsCALL
    {
        // it should propagate the revert
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.forceRevert.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, _callType, _hookAddress))
        );

        vm.expectRevert(MockFallback.FallbackRevert.selector);
        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
    }

    function test_GivenCallTypeIsDELEGATECALL_Hook1()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredWithHookSetToAddress1
        givenCallTypeIsDELEGATECALL
    {
        // it should delegatecall the target with msgdata
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.testFunction.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, _callType, _hookAddress))
        );

        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
        assertTrue(success, "Delegatecall should succeed");
    }

    function test_WhenTheDelegatecallSucceeds_Hook1()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredWithHookSetToAddress1
        givenCallTypeIsDELEGATECALL
    {
        // it should return the delegatecall result
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.testFunction.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, _callType, _hookAddress))
        );

        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
        assertTrue(success, "Should return delegatecall result");
    }

    function test_WhenTheDelegatecallReverts_Hook1()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredWithHookSetToAddress1
        givenCallTypeIsDELEGATECALL
    {
        // it should propagate the revert
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.forceRevert.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, _callType, _hookAddress))
        );

        vm.expectRevert(MockFallback.FallbackRevert.selector);
        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
    }

    function test_GivenCallTypeIsUnsupported_Hook1()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredWithHookSetToAddress1
    {
        // it should revert with InvalidCallType error
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.getCaller.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, bytes1(0x02), address(1)))
        );

        vm.expectRevert(InvalidCallType.selector);
        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
    }

    /*//////////////////////////////////////////////////////////////
                    HOOK = CONTRACT BRANCH
    //////////////////////////////////////////////////////////////*/

    modifier givenTheSelectorIsRegisteredWithAHookContract() {
        _hookAddress = address(hook);
        _;
    }

    function test_GivenTheSelectorIsRegisteredWithAHookContract()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredWithAHookContract
    {
        // it should call preHook on the hook with msgdata
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.getCaller.selector;
        _installFallback(testSelector);
        _preHookSucceeds = true;
        _configureHook();
        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
        assertTrue(success, "Call should succeed");
        assertTrue(hook.preHookCalled(), "preHook should be called");
    }

    function test_GivenPreHookReverts()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredWithAHookContract
    {
        // it should propagate the revert
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.getCaller.selector;
        _installFallback(testSelector);
        _preHookSucceeds = false;
        _configureHook();
        vm.expectRevert(MockHook.PreHookReverted.selector);
        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
    }

    modifier givenPreHookSucceeds() {
        _preHookSucceeds = true;
        _;
    }

    function test_GivenCallTypeIsCALL_GivenCallTypeIsCALL_GivenPreHookSucceeds()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredWithAHookContract
        givenPreHookSucceeds
        givenCallTypeIsCALL
    {
        // it should call the target with msgdata plus msgsender
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.getCaller.selector;
        _installFallback(testSelector);
        _configureHook();

        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
        assertTrue(success, "Should call target with msgdata plus msgsender");
    }

    modifier whenTheTargetCallSucceeds() {
        _targetCallSucceeds = true;
        _;
    }

    function test_WhenTheTargetCallSucceeds_WhenTheTargetCallSucceeds()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredWithAHookContract
        givenPreHookSucceeds
        givenCallTypeIsCALL
        whenTheTargetCallSucceeds
    {
        // it should call postHook with the context from preHook
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = _targetSelector();
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, _callType, _hookAddress))
        );

        hook.resetState();
        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
        assertTrue(success, "Call should succeed");
        assertTrue(hook.postHookCalled(), "postHook should be called with context");
    }

    function test_WhenTheTargetCallSucceeds_HookContract()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredWithAHookContract
        givenPreHookSucceeds
        givenCallTypeIsCALL
        whenTheTargetCallSucceeds
    {
        // it should call postHook with the context from preHook
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.getCaller.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, _callType, _hookAddress))
        );

        hook.resetState();
        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
        assertTrue(success, "Call should succeed");
        assertTrue(hook.postHookCalled(), "postHook should be called");
    }

    function test_GivenPostHookReverts()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredWithAHookContract
        givenPreHookSucceeds
        givenCallTypeIsCALL
        whenTheTargetCallSucceeds
    {
        // it should propagate the revert
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.getCaller.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, _callType, _hookAddress))
        );

        hook.setRevertOnPostHook(true);
        vm.expectRevert(MockHook.PostHookReverted.selector);
        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
    }

    function test_GivenPostHookSucceeds()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredWithAHookContract
        givenPreHookSucceeds
        givenCallTypeIsCALL
        whenTheTargetCallSucceeds
    {
        // it should return the call result
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.getCaller.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, _callType, _hookAddress))
        );

        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
        assertTrue(success, "Should return call result");
    }

    function test_WhenTheTargetCallReverts_GivenCallTypeIsCALL_GivenPreHookSucceeds()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredWithAHookContract
        givenPreHookSucceeds
        givenCallTypeIsCALL
    {
        // it should propagate the revert and skip postHook
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.forceRevert.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, _callType, _hookAddress))
        );

        hook.resetState();
        vm.expectRevert(MockFallback.FallbackRevert.selector);
        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
    }

    function test_GivenCallTypeIsDELEGATECALL_GivenCallTypeIsDELEGATECALL_GivenPreHookSucceeds()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredWithAHookContract
        givenPreHookSucceeds
        givenCallTypeIsDELEGATECALL
    {
        // it should delegatecall the target with msgdata
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.testFunction.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, _callType, _hookAddress))
        );

        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
        assertTrue(success, "Should delegatecall target with msgdata");
    }

    function test_WhenTheTargetCallReverts_HookContract()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredWithAHookContract
        givenPreHookSucceeds
        givenCallTypeIsCALL
    {
        // it should propagate the revert and skip postHook
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.forceRevert.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, _callType, _hookAddress))
        );

        hook.resetState();
        vm.expectRevert(MockFallback.FallbackRevert.selector);
        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
    }

    function test_GivenCallTypeIsDELEGATECALL_HookContract()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredWithAHookContract
        givenPreHookSucceeds
        givenCallTypeIsDELEGATECALL
    {
        // it should delegatecall the target with msgdata
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.testFunction.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, _callType, _hookAddress))
        );

        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
        assertTrue(success, "Delegatecall should succeed");
    }

    modifier whenTheDelegatecallSucceeds() {
        _targetCallSucceeds = true;
        _;
    }

    function test_WhenTheDelegatecallSucceeds_WhenTheDelegatecallSucceeds()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredWithAHookContract
        givenPreHookSucceeds
        givenCallTypeIsDELEGATECALL
        whenTheDelegatecallSucceeds
    {
        // it should call postHook with the context from preHook
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = _targetSelector();
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, _callType, _hookAddress))
        );

        hook.resetState();
        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
        assertTrue(success, "Delegatecall should succeed");
        assertTrue(hook.postHookCalled(), "postHook should be called with context");
    }

    function test_GivenPostHookReverts_WhenTheDelegatecallSucceeds()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredWithAHookContract
        givenPreHookSucceeds
        givenCallTypeIsDELEGATECALL
        whenTheDelegatecallSucceeds
    {
        // it should propagate the revert
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.testFunction.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, _callType, _hookAddress))
        );

        hook.setRevertOnPostHook(true);
        vm.expectRevert(MockHook.PostHookReverted.selector);
        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
    }

    function test_GivenPostHookSucceeds_WhenTheDelegatecallSucceeds()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredWithAHookContract
        givenPreHookSucceeds
        givenCallTypeIsDELEGATECALL
        whenTheDelegatecallSucceeds
    {
        // it should return the delegatecall result
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.testFunction.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, _callType, _hookAddress))
        );

        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
        assertTrue(success, "Should return delegatecall result");
    }

    function test_WhenTheDelegatecallReverts_GivenCallTypeIsDELEGATECALL_GivenPreHookSucceeds()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredWithAHookContract
        givenPreHookSucceeds
        givenCallTypeIsDELEGATECALL
    {
        // it should propagate the revert and skip postHook
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.forceRevert.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, _callType, _hookAddress))
        );

        hook.resetState();
        vm.expectRevert(MockFallback.FallbackRevert.selector);
        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
    }

    function test_GivenCallTypeIsUnsupported_GivenPreHookSucceeds()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredWithAHookContract
        givenPreHookSucceeds
    {
        // it should revert with InvalidCallType error
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.getCaller.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, bytes1(0x02), address(hook)))
        );

        vm.expectRevert(InvalidCallType.selector);
        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
    }

    function test_WhenTheDelegatecallSucceeds_HookContract()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredWithAHookContract
        givenPreHookSucceeds
        givenCallTypeIsDELEGATECALL
        whenTheDelegatecallSucceeds
    {
        // it should call postHook with the context from preHook
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.testFunction.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, _callType, _hookAddress))
        );

        hook.resetState();
        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
        assertTrue(success, "Delegatecall should succeed");
        assertTrue(hook.postHookCalled(), "postHook should be called");
    }

    function test_GivenPostHookReverts_Delegatecall()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredWithAHookContract
        givenPreHookSucceeds
        givenCallTypeIsDELEGATECALL
        whenTheDelegatecallSucceeds
    {
        // it should propagate the revert
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.testFunction.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, _callType, _hookAddress))
        );

        hook.setRevertOnPostHook(true);
        vm.expectRevert(MockHook.PostHookReverted.selector);
        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
    }

    function test_GivenPostHookSucceeds_Delegatecall()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredWithAHookContract
        givenPreHookSucceeds
        givenCallTypeIsDELEGATECALL
        whenTheDelegatecallSucceeds
    {
        // it should return the delegatecall result
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.testFunction.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, _callType, _hookAddress))
        );

        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
        assertTrue(success, "Should return delegatecall result");
    }

    function test_WhenTheDelegatecallReverts_HookContract()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredWithAHookContract
        givenPreHookSucceeds
        givenCallTypeIsDELEGATECALL
    {
        // it should propagate the revert and skip postHook
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.forceRevert.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, _callType, _hookAddress))
        );

        vm.expectRevert(MockFallback.FallbackRevert.selector);
        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
    }

    function test_GivenCallTypeIsUnsupported_HookContract()
        external
        whenTheSelectorIsACustomRegisteredSelector
        givenTheSelectorIsRegisteredWithAHookContract
        givenPreHookSucceeds
    {
        // it should revert with InvalidCallType error
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.getCaller.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, bytes1(0x02), address(hook)))
        );

        vm.expectRevert(InvalidCallType.selector);
        (bool success,) = address(kernel).call(abi.encodeWithSelector(testSelector));
    }

    /*//////////////////////////////////////////////////////////////
                            HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _installFallback(bytes4 selector) internal {
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(selector, _callType, _hookAddress))
        );
    }

    function _configureHook() internal {
        hook.resetState();
        hook.setRevertOnPreHook(!_preHookSucceeds);
    }

    function _targetSelector() internal view returns (bytes4) {
        if (_targetCallSucceeds) {
            return _callType == bytes1(0xff) ? MockFallback.testFunction.selector : MockFallback.getCaller.selector;
        }
        return MockFallback.forceRevert.selector;
    }
}
