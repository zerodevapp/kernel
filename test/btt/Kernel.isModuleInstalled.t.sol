// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {BTTModifiers} from "./BTTModifiers.sol";
import {MockValidator} from "../mock/MockValidator.sol";
import {MockExecutor} from "../mock/MockExecutor.sol";
import {MockFallback} from "../mock/MockFallback.sol";
import {MockHook} from "../mock/MockHook.sol";
import {MockPolicy} from "../mock/MockPolicy.sol";
import {MockSigner} from "../mock/MockSigner.sol";
import {NotImplemented} from "src/types/Error.sol";
import {SCOPED_EXECUTION_HOOK_VALIDATION_SCOPE} from "src/types/Constants.sol";
import {permissionToIdentifier} from "src/lib/Utils.sol";

/// @title Kernel.isModuleInstalled BTT Tests
/// @notice Tests for isModuleInstalled following Branching Tree Technique
/// @dev Tree specification: test/btt/Kernel.isModuleInstalled.tree
abstract contract Kernel_isModuleInstalled is BTTModifiers {
    // Note: _moduleTypeId is inherited from BTTModifiers

    /*//////////////////////////////////////////////////////////////
                        VALIDATOR (TYPE 1) TESTS
    //////////////////////////////////////////////////////////////*/

    modifier givenModuleTypeIdIs1Validator() {
        _moduleTypeId = 1;
        _;
    }

    function test_GivenTheValidatorIsInstalled() external givenModuleTypeIdIs1Validator {
        // Install validator first
        MockValidator mockValidator = new MockValidator();
        vm.prank(address(ep));
        kernel.installModule(1, address(mockValidator), abi.encode(hex"", hex""));

        assertTrue(kernel.isModuleInstalled(1, address(mockValidator), ""), "Installed validator should return true");
    }

    function test_GivenTheValidatorIsNotInstalled() external givenModuleTypeIdIs1Validator {
        MockValidator mockValidator = new MockValidator();
        assertFalse(
            kernel.isModuleInstalled(1, address(mockValidator), ""), "Not installed validator should return false"
        );
    }

    /*//////////////////////////////////////////////////////////////
                        EXECUTOR (TYPE 2) TESTS
    //////////////////////////////////////////////////////////////*/

    modifier givenModuleTypeIdIs2Executor() {
        _moduleTypeId = 2;
        _;
    }

    function test_GivenTheExecutorIsInstalled() external givenModuleTypeIdIs2Executor {
        MockExecutor mockExecutor = new MockExecutor();
        vm.prank(address(ep));
        kernel.installModule(2, address(mockExecutor), abi.encode(hex"", hex""));

        assertTrue(kernel.isModuleInstalled(2, address(mockExecutor), ""), "Installed executor should return true");
    }

    function test_GivenTheExecutorIsNotInstalled() external givenModuleTypeIdIs2Executor {
        MockExecutor mockExecutor = new MockExecutor();
        assertFalse(
            kernel.isModuleInstalled(2, address(mockExecutor), ""), "Not installed executor should return false"
        );
    }

    /*//////////////////////////////////////////////////////////////
                        FALLBACK (TYPE 3) TESTS
    //////////////////////////////////////////////////////////////*/

    modifier givenModuleTypeIdIs3Fallback() {
        _moduleTypeId = 3;
        _;
    }

    function test_GivenTheSelectorIsRegisteredToTheModule() external givenModuleTypeIdIs3Fallback {
        MockFallback mockFallback = new MockFallback();
        bytes4 selector = bytes4(keccak256("customFunction()"));

        // Install fallback with selector
        bytes memory internalData = abi.encodePacked(selector, bytes1(0x00));
        vm.prank(address(ep));
        kernel.installModule(3, address(mockFallback), abi.encode(hex"", internalData));

        assertTrue(
            kernel.isModuleInstalled(3, address(mockFallback), abi.encodePacked(selector)),
            "Registered selector should return true"
        );
    }

    function test_GivenTheSelectorIsNotRegisteredToTheModule() external givenModuleTypeIdIs3Fallback {
        MockFallback mockFallback = new MockFallback();
        bytes4 selector = bytes4(keccak256("customFunction()"));

        assertFalse(
            kernel.isModuleInstalled(3, address(mockFallback), abi.encodePacked(selector)),
            "Unregistered selector should return false"
        );
    }

    /*//////////////////////////////////////////////////////////////
                    EXECUTION HOOK (TYPE 11) TESTS
    //////////////////////////////////////////////////////////////*/

    function test_GivenTheScopedExecutionHookIsInstalled() external {
        MockSigner mockSigner = new MockSigner();
        MockHook mockHook = new MockHook();
        bytes memory context =
            abi.encodePacked(SCOPED_EXECUTION_HOOK_VALIDATION_SCOPE, permissionToIdentifier(permissionId));
        vm.startPrank(address(ep));
        kernel.installModule(6, address(mockSigner), abi.encode(hex"", abi.encodePacked(permissionId)));
        kernel.installModule(11, address(mockHook), abi.encode(hex"", context));
        vm.stopPrank();

        assertTrue(
            kernel.isModuleInstalled(11, address(mockHook), context),
            "Installed scoped execution hook should return true"
        );
    }

    function test_GivenTheScopedExecutionHookIsNotInstalled() external {
        MockHook mockHook = new MockHook();
        bytes memory context =
            abi.encodePacked(SCOPED_EXECUTION_HOOK_VALIDATION_SCOPE, permissionToIdentifier(permissionId));
        assertFalse(
            kernel.isModuleInstalled(11, address(mockHook), context),
            "Uninstalled scoped execution hook should return false"
        );
        assertFalse(
            kernel.isModuleInstalled(11, address(mockHook), hex""),
            "Empty scoped execution hook context should return false"
        );
    }

    /*//////////////////////////////////////////////////////////////
                        POLICY (TYPE 5) TESTS
    //////////////////////////////////////////////////////////////*/

    modifier givenModuleTypeIdIs5Policy() {
        _moduleTypeId = 5;
        _;
    }

    function test_GivenThePermissionIdHasThisPolicyInstalled() external givenModuleTypeIdIs5Policy {
        MockPolicy mockPolicy = new MockPolicy();
        bytes memory internalData = abi.encodePacked(permissionId);

        vm.prank(address(ep));
        kernel.installModule(5, address(mockPolicy), abi.encode(hex"", internalData));

        assertTrue(
            kernel.isModuleInstalled(5, address(mockPolicy), abi.encodePacked(permissionId)),
            "Installed policy should return true"
        );
    }

    function test_GivenThePermissionIdDoesNotHaveThisPolicy() external givenModuleTypeIdIs5Policy {
        MockPolicy mockPolicy = new MockPolicy();
        assertFalse(
            kernel.isModuleInstalled(5, address(mockPolicy), abi.encodePacked(permissionId)),
            "Not installed policy should return false"
        );
    }

    /*//////////////////////////////////////////////////////////////
                        SIGNER (TYPE 6) TESTS
    //////////////////////////////////////////////////////////////*/

    modifier givenModuleTypeIdIs6Signer() {
        _moduleTypeId = 6;
        _;
    }

    function test_GivenThePermissionIdHasThisSignerInstalled() external givenModuleTypeIdIs6Signer {
        // Install policy first (required before signer)
        MockPolicy mockPolicy = new MockPolicy();
        bytes memory policyInternalData = abi.encodePacked(permissionId);
        vm.prank(address(ep));
        kernel.installModule(5, address(mockPolicy), abi.encode(hex"", policyInternalData));

        // Install signer
        MockSigner mockSigner = new MockSigner();
        bytes memory signerInternalData = abi.encodePacked(permissionId);
        vm.prank(address(ep));
        kernel.installModule(6, address(mockSigner), abi.encode(hex"", signerInternalData));

        assertTrue(
            kernel.isModuleInstalled(6, address(mockSigner), abi.encodePacked(permissionId)),
            "Installed signer should return true"
        );
    }

    function test_GivenThePermissionIdDoesNotHaveThisSigner() external givenModuleTypeIdIs6Signer {
        MockSigner mockSigner = new MockSigner();
        assertFalse(
            kernel.isModuleInstalled(6, address(mockSigner), abi.encodePacked(permissionId)),
            "Not installed signer should return false"
        );
    }

    /*//////////////////////////////////////////////////////////////
                        UNSUPPORTED TYPE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_GivenModuleTypeIdIsUnsupported() external {
        vm.expectRevert(NotImplemented.selector);
        kernel.isModuleInstalled(4, address(0x123), "");
        vm.expectRevert(NotImplemented.selector);
        kernel.isModuleInstalled(7, address(0x123), "");
    }
}
