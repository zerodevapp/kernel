// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {BTTModifiers} from "./BTTModifiers.sol";
import {Kernel} from "src/Kernel.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {KernelImmutableECDSA} from "src/KernelImmutableECDSA.sol";
import {KernelFactory} from "src/KernelFactory.sol";
import {Install} from "src/types/Structs.sol";
import {MockValidator} from "../mock/MockValidator.sol";
import {MockExecutor} from "../mock/MockExecutor.sol";
import {MockPolicy} from "../mock/MockPolicy.sol";
import {MockSigner} from "../mock/MockSigner.sol";
import {MockHook} from "../mock/MockHook.sol";
import {IValidator} from "src/interfaces/IERC7579Modules.sol";
import {PermissionId} from "src/types/Types.sol";
import {validatorToIdentifier, permissionToIdentifier} from "src/lib/Utils.sol";
import {
    InvalidInitialization,
    InvalidRootValidation,
    InvalidPermissionId,
    PermissionInstallNotFinished
} from "src/types/Error.sol";

/// @title Kernel.initialize BTT Tests
/// @notice Tests for initialize following Branching Tree Technique
/// @dev Tree specification: test/btt/Kernel.initialize.tree
abstract contract Kernel_initialize is BTTModifiers {
    // State variables for initialize branch tracking
    bool internal _accountNotInitialized;
    bool internal _packagesNotEmpty;
    bool internal _firstPackageIsPermission;

    function test_GivenTheAccountHasAlreadyBeenInitialized() external {
        // The kernel is already initialized in setUp, trying to initialize again should fail
        Install[] memory packages = new Install[](1);
        MockValidator mockValidator = new MockValidator();
        packages[0] = Install({moduleType: 1, module: address(mockValidator), moduleData: hex"", internalData: hex""});

        vm.expectRevert(InvalidInitialization.selector);
        kernel.initialize(packages);
    }

    modifier givenTheAccountHasNotBeenInitialized() {
        _accountNotInitialized = true;
        _;
    }

    function test_WhenPackagesArrayIsEmpty() external givenTheAccountHasNotBeenInitialized {
        // Deploy a new kernel without initializing
        Install[] memory emptyPackages = new Install[](0);

        // it should revert with InvalidInitialization error
        vm.expectRevert(InvalidInitialization.selector);
        factory.deploy(emptyPackages, 999);
    }

    modifier whenPackagesArrayHasOneOrMoreElements() {
        _packagesNotEmpty = true;
        _;
    }

    function test_WhenPackagesArrayHasOneOrMoreElements()
        external
        givenTheAccountHasNotBeenInitialized
        whenPackagesArrayHasOneOrMoreElements
    {
        // Deploy new kernel with multiple packages
        MockValidator mockValidator = new MockValidator();
        MockExecutor mockExecutor = new MockExecutor();

        Install[] memory packages = new Install[](2);
        packages[0] = Install({moduleType: 1, module: address(mockValidator), moduleData: hex"", internalData: hex""});
        packages[1] = Install({moduleType: 2, module: address(mockExecutor), moduleData: hex"", internalData: hex""});

        Kernel newKernel = Kernel(payable(factory.deploy(packages, 1000)));

        // Both modules should be installed
        assertTrue(newKernel.isModuleInstalled(1, address(mockValidator), ""), "Validator should be installed");
        assertTrue(newKernel.isModuleInstalled(2, address(mockExecutor), ""), "Executor should be installed");
    }

    function test_GivenTheFirstPackageIsAValidator()
        external
        givenTheAccountHasNotBeenInitialized
        whenPackagesArrayHasOneOrMoreElements
    {
        MockValidator mockValidator = new MockValidator();

        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(mockValidator), moduleData: hex"", internalData: hex""});

        Kernel newKernel = Kernel(payable(factory.deploy(packages, 1001)));

        // Validator should be installed and set as root
        assertTrue(newKernel.isModuleInstalled(1, address(mockValidator), ""), "Validator should be installed");

        // Check root is set (hook should be address(1) for root)
        assertEq(
            newKernel.validationInfo(validatorToIdentifier(IValidator(address(mockValidator)))).hook,
            address(1),
            "Validator should be set as root"
        );
    }

    modifier givenTheFirstPackageIsAPermission() {
        _firstPackageIsPermission = true;
        _;
    }

    function test_GivenThereAreBothPolicyAndSignerPackages()
        external
        givenTheAccountHasNotBeenInitialized
        whenPackagesArrayHasOneOrMoreElements
        givenTheFirstPackageIsAPermission
    {
        MockPolicy mockPolicy = new MockPolicy();
        MockSigner mockSigner = new MockSigner();
        PermissionId testPermId = PermissionId.wrap(bytes4(keccak256("initTestPermission")));

        Install[] memory packages = new Install[](2);
        packages[0] = Install({
            moduleType: 5, module: address(mockPolicy), moduleData: hex"", internalData: abi.encodePacked(testPermId)
        });
        packages[1] = Install({
            moduleType: 6, module: address(mockSigner), moduleData: hex"", internalData: abi.encodePacked(testPermId)
        });

        Kernel newKernel = Kernel(payable(factory.deploy(packages, 1002)));

        // Both policy and signer should be installed
        assertTrue(
            newKernel.isModuleInstalled(5, address(mockPolicy), abi.encodePacked(testPermId)),
            "Policy should be installed"
        );
        assertTrue(
            newKernel.isModuleInstalled(6, address(mockSigner), abi.encodePacked(testPermId)),
            "Signer should be installed"
        );

        // Permission should be set as root (hook should be address(1))
        assertEq(
            newKernel.validationInfo(permissionToIdentifier(testPermId)).hook,
            address(1),
            "Permission should be set as root"
        );
    }

    function test_GivenThePermissionSetupIsIncomplete()
        external
        givenTheAccountHasNotBeenInitialized
        whenPackagesArrayHasOneOrMoreElements
        givenTheFirstPackageIsAPermission
    {
        // Only install policy without signer - this should revert during deployment
        // because the permission is incomplete (no signer means root cannot be set)
        MockPolicy mockPolicy = new MockPolicy();
        PermissionId testPermId = PermissionId.wrap(bytes4(keccak256("incompletePermission")));

        Install[] memory packages = new Install[](1);
        packages[0] = Install({
            moduleType: 5, module: address(mockPolicy), moduleData: hex"", internalData: abi.encodePacked(testPermId)
        });

        // Deploying with only policy (no signer) should revert
        vm.expectRevert(PermissionInstallNotFinished.selector);
        factory.deploy(packages, 1003);
    }

    function test_GivenTheFirstPackageIsNotAValidatorOrPermission()
        external
        givenTheAccountHasNotBeenInitialized
        whenPackagesArrayHasOneOrMoreElements
    {
        // it should revert with InvalidRootValidation error
        MockExecutor mockExecutor = new MockExecutor();

        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 2, module: address(mockExecutor), moduleData: hex"", internalData: hex""});

        // First package is an executor (type 2), not a validator (type 1) or permission (type 5/6)
        vm.expectRevert(InvalidRootValidation.selector);
        factory.deploy(packages, 1005);
    }

    function test_GivenSubsequentPackagesContainExecutorsHooksOrFallbacks()
        external
        givenTheAccountHasNotBeenInitialized
        whenPackagesArrayHasOneOrMoreElements
    {
        MockValidator mockValidator = new MockValidator();
        MockExecutor mockExecutor = new MockExecutor();
        MockHook mockHook = new MockHook();

        Install[] memory packages = new Install[](3);
        packages[0] = Install({moduleType: 1, module: address(mockValidator), moduleData: hex"", internalData: hex""});
        packages[1] = Install({moduleType: 2, module: address(mockExecutor), moduleData: hex"", internalData: hex""});
        packages[2] = Install({moduleType: 4, module: address(mockHook), moduleData: hex"", internalData: hex""});

        Kernel newKernel = Kernel(payable(factory.deploy(packages, 1004)));

        // All modules should be installed
        assertTrue(newKernel.isModuleInstalled(1, address(mockValidator), ""), "Validator should be installed");
        assertTrue(newKernel.isModuleInstalled(2, address(mockExecutor), ""), "Executor should be installed");
        assertTrue(newKernel.isModuleInstalled(4, address(mockHook), ""), "Hook should be installed");
    }
}
