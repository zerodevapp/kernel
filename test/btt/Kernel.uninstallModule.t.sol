// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {BTTModifiers} from "./BTTModifiers.sol";
import {MockValidator} from "../mock/MockValidator.sol";
import {MockExecutor} from "../mock/MockExecutor.sol";
import {MockHook} from "../mock/MockHook.sol";
import {MockFallback} from "../mock/MockFallback.sol";
import {MockPolicy} from "../mock/MockPolicy.sol";
import {MockSigner} from "../mock/MockSigner.sol";
import {IValidator} from "src/interfaces/IERC7579Modules.sol";
import {validatorToIdentifier, permissionToIdentifier} from "src/lib/Utils.sol";
import {PermissionId} from "src/types/Types.sol";
import {Unauthorized, NotImplemented, InvalidPermissionUninstallOrder, InvalidPermissionId} from "src/types/Error.sol";

/// @title Kernel.uninstallModule BTT Tests
/// @notice Tests for uninstallModule following Branching Tree Technique
/// @dev Tree specification: test/btt/Kernel.uninstallModule.tree
abstract contract Kernel_uninstallModule is BTTModifiers {
    uint256 internal _uninstallModuleTypeId;

    /*//////////////////////////////////////////////////////////////
                        UNAUTHORIZED CALLER TESTS
    //////////////////////////////////////////////////////////////*/

    function test_WhenTheCallerIsNotTheEntryPointUninstall() external whenTheCallerIsNotTheEntryPointUninstall {
        vm.expectRevert(Unauthorized.selector);
        kernel.uninstallModule(1, address(newValidator), abi.encode(hex"", hex""));
    }

    modifier whenTheCallerIsTheEntryPointOrSelfUninstall() {
        vm.stopPrank();
        vm.startPrank(address(ep));
        _;
    }

    modifier givenModuleTypeIsValidatorUninstall() {
        _uninstallModuleTypeId = 1;
        _;
    }

    function test_GivenTheValidatorIsInstalledUninstall()
        external
        whenTheCallerIsTheEntryPointOrSelfUninstall
        givenModuleTypeIsValidatorUninstall
    {
        // it should clear validator hook state
        MockValidator mockValidator = new MockValidator();
        kernel.installModule(1, address(mockValidator), abi.encode(hex"", hex""));

        // Verify it's installed
        assertTrue(
            kernel.validationInfo(validatorToIdentifier(IValidator(address(mockValidator)))).installed,
            "Validator should be installed"
        );

        // Uninstall
        kernel.uninstallModule(1, address(mockValidator), abi.encode(hex"", hex""));

        // Verify hook state is cleared
        assertFalse(
            kernel.validationInfo(validatorToIdentifier(IValidator(address(mockValidator)))).installed,
            "Validator hook should be cleared"
        );
    }

    function test_GivenTheValidatorIsNotInstalledUninstall()
        external
        whenTheCallerIsTheEntryPointOrSelfUninstall
        givenModuleTypeIsValidatorUninstall
    {
        // it should be a no-op and leave root unchanged
        MockValidator mockValidator = new MockValidator();

        // Validator is NOT installed - uninstall should be a no-op
        kernel.uninstallModule(1, address(mockValidator), abi.encode(hex"", hex""));

        // Verify it remains uninstalled (hook is still address(0))
        assertFalse(
            kernel.validationInfo(validatorToIdentifier(IValidator(address(mockValidator)))).installed,
            "Validator should remain uninstalled"
        );
    }

    function test_GivenModuleTypeIsValidatorUninstall()
        external
        whenTheCallerIsTheEntryPointOrSelfUninstall
        givenModuleTypeIsValidatorUninstall
    {
        MockValidator mockValidator = new MockValidator();
        kernel.installModule(1, address(mockValidator), abi.encode(hex"", hex""));

        kernel.uninstallModule(1, address(mockValidator), abi.encode(hex"", hex""));

        // Verify the validator is no longer installed (hook is cleared)
        assertFalse(
            kernel.validationInfo(validatorToIdentifier(IValidator(address(mockValidator)))).installed,
            "Validator hook should be cleared"
        );
    }

    function test_GivenTheValidatorIsNotTheRoot()
        external
        whenTheCallerIsTheEntryPointOrSelfUninstall
        givenModuleTypeIsValidatorUninstall
    {
        // Install a non-root validator
        MockValidator mockValidator = new MockValidator();
        kernel.installModule(1, address(mockValidator), abi.encode(hex"", hex""));

        // Verify it's installed
        assertTrue(kernel.isModuleInstalled(1, address(mockValidator), ""), "Validator should be installed");

        // Uninstall it
        kernel.uninstallModule(1, address(mockValidator), abi.encode(hex"", hex""));

        // Verify it's uninstalled
        assertFalse(kernel.isModuleInstalled(1, address(mockValidator), ""), "Validator should be uninstalled");
    }

    modifier givenModuleTypeIsExecutorUninstall() {
        _uninstallModuleTypeId = 2;
        _;
    }

    function test_GivenModuleTypeIsExecutorUninstall()
        external
        whenTheCallerIsTheEntryPointOrSelfUninstall
        givenModuleTypeIsExecutorUninstall
    {
        MockExecutor mockExecutor = new MockExecutor();
        kernel.installModule(2, address(mockExecutor), abi.encode(hex"", hex""));

        kernel.uninstallModule(2, address(mockExecutor), abi.encode(hex"", hex""));

        // Verify the executor is no longer installed
        assertFalse(kernel.isModuleInstalled(2, address(mockExecutor), ""), "Executor should be uninstalled");
    }

    function test_GivenModuleTypeIsFallbackUninstall() external whenTheCallerIsTheEntryPointOrSelfUninstall {
        // it should clear selector config for the selector
        MockFallback mockFallback = new MockFallback();
        bytes4 selector = bytes4(keccak256("testFallback()"));
        bytes memory internalData = abi.encodePacked(selector, bytes1(0x00));

        kernel.installModule(3, address(mockFallback), abi.encode(hex"", internalData));

        assertTrue(
            kernel.isModuleInstalled(3, address(mockFallback), abi.encodePacked(selector)),
            "Fallback should be installed"
        );

        kernel.uninstallModule(3, address(mockFallback), abi.encode(hex"", abi.encodePacked(selector)));

        assertFalse(
            kernel.isModuleInstalled(3, address(mockFallback), abi.encodePacked(selector)),
            "Fallback selector config should be cleared"
        );
    }

    modifier givenModuleTypeIsFallbackUninstall() {
        _uninstallModuleTypeId = 3;
        _;
    }

    modifier givenModuleTypeIsHookUninstall() {
        _uninstallModuleTypeId = 4;
        _;
    }

    modifier givenModuleTypeIsPolicyUninstall() {
        _uninstallModuleTypeId = 5;
        _;
    }

    function test_GivenThePolicyIsTheLastInstalledPolicy()
        external
        whenTheCallerIsTheEntryPointOrSelfUninstall
        givenModuleTypeIsPolicyUninstall
    {
        // it should pop the policy from the list
        MockPolicy mockPolicy = new MockPolicy();
        PermissionId testPermId = PermissionId.wrap(bytes4(keccak256("lastPolicyTest")));
        bytes memory internalData = abi.encodePacked(testPermId);

        kernel.installModule(5, address(mockPolicy), abi.encode(hex"", internalData));

        assertTrue(
            kernel.isModuleInstalled(5, address(mockPolicy), abi.encodePacked(testPermId)), "Policy should be installed"
        );

        // Uninstall the last (and only) policy
        kernel.uninstallModule(5, address(mockPolicy), abi.encode(hex"", internalData));

        assertFalse(
            kernel.isModuleInstalled(5, address(mockPolicy), abi.encodePacked(testPermId)),
            "Policy should be uninstalled"
        );
    }

    function test_GivenThePolicyIsNotTheLastInstalledPolicy()
        external
        whenTheCallerIsTheEntryPointOrSelfUninstall
        givenModuleTypeIsPolicyUninstall
    {
        // it should revert with InvalidPermissionUninstallOrder error
        MockPolicy mockPolicy1 = new MockPolicy();
        MockPolicy mockPolicy2 = new MockPolicy();
        PermissionId testPermId = PermissionId.wrap(bytes4(keccak256("notLastPolicyTest")));
        bytes memory internalData = abi.encodePacked(testPermId);

        // Install two policies
        kernel.installModule(5, address(mockPolicy1), abi.encode(hex"", internalData));
        kernel.installModule(5, address(mockPolicy2), abi.encode(hex"", internalData));

        // Try to uninstall the first policy (not the last one) - should revert
        vm.expectRevert(InvalidPermissionUninstallOrder.selector);
        kernel.uninstallModule(5, address(mockPolicy1), abi.encode(hex"", internalData));
    }

    function test_GivenThePolicyIsInstalledForThisPermissionId()
        external
        whenTheCallerIsTheEntryPointOrSelfUninstall
        givenModuleTypeIsPolicyUninstall
    {
        MockPolicy mockPolicy = new MockPolicy();
        PermissionId testPermId = PermissionId.wrap(bytes4(keccak256("uninstallPolicyTest")));
        bytes memory internalData = abi.encodePacked(testPermId);

        kernel.installModule(5, address(mockPolicy), abi.encode(hex"", internalData));

        assertTrue(
            kernel.isModuleInstalled(5, address(mockPolicy), abi.encodePacked(testPermId)), "Policy should be installed"
        );

        kernel.uninstallModule(5, address(mockPolicy), abi.encode(hex"", internalData));

        assertFalse(
            kernel.isModuleInstalled(5, address(mockPolicy), abi.encodePacked(testPermId)),
            "Policy should be uninstalled"
        );
    }

    modifier givenModuleTypeIsSignerUninstall() {
        _uninstallModuleTypeId = 6;
        _;
    }

    function test_GivenPoliciesRemainInstalled()
        external
        whenTheCallerIsTheEntryPointOrSelfUninstall
        givenModuleTypeIsSignerUninstall
    {
        // it should revert with InvalidPermissionUninstallOrder error
        MockPolicy mockPolicy = new MockPolicy();
        MockSigner mockSigner = new MockSigner();
        PermissionId testPermId = PermissionId.wrap(bytes4(keccak256("policiesRemainTest")));
        bytes memory internalData = abi.encodePacked(testPermId);

        // Install policy and signer
        kernel.installModule(5, address(mockPolicy), abi.encode(hex"", internalData));
        kernel.installModule(6, address(mockSigner), abi.encode(hex"", internalData));

        // Try to uninstall signer while policy remains - should revert
        vm.expectRevert(InvalidPermissionUninstallOrder.selector);
        kernel.uninstallModule(6, address(mockSigner), abi.encode(hex"", internalData));
    }

    function test_GivenTheSignerDoesNotMatchCurrentSigner()
        external
        whenTheCallerIsTheEntryPointOrSelfUninstall
        givenModuleTypeIsSignerUninstall
    {
        // it should revert with InvalidPermissionId error
        MockPolicy mockPolicy = new MockPolicy();
        MockSigner mockSigner = new MockSigner();
        MockSigner wrongSigner = new MockSigner();
        PermissionId testPermId = PermissionId.wrap(bytes4(keccak256("wrongSignerTest")));
        bytes memory internalData = abi.encodePacked(testPermId);

        // Install policy and signer
        kernel.installModule(5, address(mockPolicy), abi.encode(hex"", internalData));
        kernel.installModule(6, address(mockSigner), abi.encode(hex"", internalData));

        // Uninstall policy first
        kernel.uninstallModule(5, address(mockPolicy), abi.encode(hex"", internalData));

        // Try to uninstall a different signer - should revert
        vm.expectRevert(InvalidPermissionId.selector);
        kernel.uninstallModule(6, address(wrongSigner), abi.encode(hex"", internalData));
    }

    function test_GivenTheSignerMatchesAndNoPoliciesRemain()
        external
        whenTheCallerIsTheEntryPointOrSelfUninstall
        givenModuleTypeIsSignerUninstall
    {
        // it should clear signer and hook state
        MockPolicy mockPolicy = new MockPolicy();
        MockSigner mockSigner = new MockSigner();
        PermissionId testPermId = PermissionId.wrap(bytes4(keccak256("clearSignerTest")));
        bytes memory internalData = abi.encodePacked(testPermId);

        // Install policy and signer
        kernel.installModule(5, address(mockPolicy), abi.encode(hex"", internalData));
        kernel.installModule(6, address(mockSigner), abi.encode(hex"", internalData));

        // Verify signer is installed
        assertTrue(
            kernel.isModuleInstalled(6, address(mockSigner), abi.encodePacked(testPermId)), "Signer should be installed"
        );

        // Uninstall policy first
        kernel.uninstallModule(5, address(mockPolicy), abi.encode(hex"", internalData));

        // Now uninstall signer
        kernel.uninstallModule(6, address(mockSigner), abi.encode(hex"", internalData));

        // Verify signer and hook state are cleared
        assertFalse(
            kernel.isModuleInstalled(6, address(mockSigner), abi.encodePacked(testPermId)),
            "Signer should be uninstalled"
        );
        assertFalse(
            kernel.validationInfo(permissionToIdentifier(testPermId)).installed, "Permission should be uninstalled"
        );
    }

    function test_GivenModuleTypeIsUnsupported() external whenTheCallerIsTheEntryPointOrSelfUninstall {
        vm.expectRevert(NotImplemented.selector);
        kernel.uninstallModule(7, address(0x123), abi.encode(hex"", hex""));
    }

    modifier whenTheCallerIsNotTheEntryPointUninstall() {
        vm.stopPrank();
        vm.startPrank(makeAddr("randomCaller"));
        _;
    }

    /*//////////////////////////////////////////////////////////////
                        VALIDATOR UNINSTALL TESTS
    //////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                        EXECUTOR UNINSTALL TESTS
    //////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                        FALLBACK UNINSTALL TESTS
    //////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                        HOOK UNINSTALL TESTS
    //////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                        POLICY UNINSTALL TESTS
    //////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                        SIGNER UNINSTALL TESTS
    //////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                    UNSUPPORTED MODULE TYPE TESTS
    //////////////////////////////////////////////////////////////*/
}
