// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {BTTModifiers} from "./BTTModifiers.sol";
import {Kernel} from "src/Kernel.sol";
import {Install} from "src/types/Structs.sol";
import {MockValidator} from "../mock/MockValidator.sol";
import {MockPolicy} from "../mock/MockPolicy.sol";
import {MockSigner} from "../mock/MockSigner.sol";
import {IValidator} from "src/interfaces/IERC7579Modules.sol";
import {ValidationId, PermissionId} from "src/types/Types.sol";
import {validatorToIdentifier, permissionToIdentifier} from "src/lib/Utils.sol";
import {
    Unauthorized,
    InvalidDataLength,
    InvalidInitialization,
    InvalidRootValidation,
    InvalidPermissionUninstallOrder
} from "src/types/Error.sol";

/// @title Kernel.setRoot BTT Tests
/// @notice Tests for setRoot following Branching Tree Technique
/// @dev Tree specification: test/btt/Kernel.setRoot.tree
abstract contract Kernel_setRoot is BTTModifiers {
    bool internal _useInstallArrayOverload;
    bool internal _removeCurrent;
    bool internal _currentRootIsPermission;
    bool internal _uninstallDataCorrectLength;

    /*//////////////////////////////////////////////////////////////
                        UNAUTHORIZED CALLER TESTS
    //////////////////////////////////////////////////////////////*/

    modifier whenCallerIsNotEntryPointSetRoot() {
        vm.stopPrank();
        vm.startPrank(makeAddr("randomCaller"));
        _useInstallArrayOverload = false;
        _removeCurrent = false;
        _;
    }

    function test_WhenCallerIsNotEntryPointSetRoot() external whenCallerIsNotEntryPointSetRoot {
        ValidationId vId = validatorToIdentifier(IValidator(address(newValidator)));
        vm.expectRevert(Unauthorized.selector);
        _callSetRoot(vId, new Install[](0), hex"");
    }

    /*//////////////////////////////////////////////////////////////
                        SETROOT(VALIDATIONID) TESTS
    //////////////////////////////////////////////////////////////*/

    modifier whenCallerIsEntryPointOrSelfSetRoot() {
        vm.stopPrank();
        vm.startPrank(address(ep));
        _;
    }

    modifier givenTheOverloadSetRootWithValidationIdIsCalled() {
        _useInstallArrayOverload = false;
        _removeCurrent = false;
        _currentRootIsPermission = false;
        _uninstallDataCorrectLength = false;
        _;
    }

    function test_GivenVIdIsZeroAndNoFallbackValidatorExists()
        external
        whenCallerIsEntryPointOrSelfSetRoot
        givenTheOverloadSetRootWithValidationIdIsCalled
    {
        // it should revert with InvalidRootValidation error
        ValidationId zeroVId = ValidationId.wrap(bytes21(0));

        vm.expectRevert(InvalidRootValidation.selector);
        _callSetRoot(zeroVId, new Install[](0), hex"");
    }

    function test_GivenVIdCorrespondsToAnInstalledValidator()
        external
        whenCallerIsEntryPointOrSelfSetRoot
        givenTheOverloadSetRootWithValidationIdIsCalled
    {
        // Install a new validator
        MockValidator mockValidator = new MockValidator();
        kernel.installModule(1, address(mockValidator), abi.encode(hex"", hex""));

        // Set it as root
        ValidationId vId = validatorToIdentifier(IValidator(address(mockValidator)));
        _callSetRoot(vId, new Install[](0), hex"");

        // Verify the root was changed
        assertTrue(kernel.validationInfo(vId).installed, "New validator should be root");
    }

    function test_GivenVIdCorrespondsToAnInstalledPermission()
        external
        whenCallerIsEntryPointOrSelfSetRoot
        givenTheOverloadSetRootWithValidationIdIsCalled
    {
        // Install policy and signer for permission
        MockPolicy mockPolicy = new MockPolicy();
        MockSigner mockSigner = new MockSigner();
        PermissionId testPermId = PermissionId.wrap(bytes4(keccak256("setRootTestPerm")));

        kernel.installModule(5, address(mockPolicy), abi.encode(hex"", abi.encodePacked(testPermId)));
        kernel.installModule(6, address(mockSigner), abi.encode(hex"", abi.encodePacked(testPermId)));

        // Set permission as root
        ValidationId vId = permissionToIdentifier(testPermId);
        _callSetRoot(vId, new Install[](0), hex"");

        // Verify the root was changed
        assertTrue(kernel.validationInfo(vId).installed, "Permission should be root");
    }

    /*//////////////////////////////////////////////////////////////
                    SETROOT(INSTALL[], BOOL, BYTES) TESTS
    //////////////////////////////////////////////////////////////*/

    modifier givenTheOverloadSetRootWithInstallArrayIsCalled() {
        _useInstallArrayOverload = true;
        _removeCurrent = false;
        _currentRootIsPermission = false;
        _uninstallDataCorrectLength = false;
        _;
    }

    function test_GivenPackagesArrayIsEmpty()
        external
        whenCallerIsEntryPointOrSelfSetRoot
        givenTheOverloadSetRootWithInstallArrayIsCalled
    {
        // it should revert with InvalidInitialization error
        Install[] memory packages = new Install[](0);

        vm.expectRevert(InvalidInitialization.selector);
        _callSetRoot(ValidationId.wrap(bytes21(0)), packages, hex"");
    }

    function test_GivenRemoveCurrentIsFalse()
        external
        whenCallerIsEntryPointOrSelfSetRoot
        givenTheOverloadSetRootWithInstallArrayIsCalled
    {
        // Install a new validator as root without removing current
        MockValidator newRoot = new MockValidator();
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(newRoot), moduleData: hex"", internalData: hex""});

        _callSetRoot(ValidationId.wrap(bytes21(0)), packages, hex"");

        // Both old root and new root should be installed
        assertTrue(kernel.isModuleInstalled(1, address(rootValidator), ""), "Old root should still be installed");
        assertTrue(kernel.isModuleInstalled(1, address(newRoot), ""), "New root should be installed");

        // New root should be the active root
        assertTrue(
            kernel.validationInfo(validatorToIdentifier(IValidator(address(newRoot)))).installed,
            "New validator should be root"
        );
    }

    modifier givenRemoveCurrentIsTrue() {
        _removeCurrent = true;
        _;
    }

    function test_GivenTheCurrentRootIsAVALIDATOR()
        external
        whenCallerIsEntryPointOrSelfSetRoot
        givenTheOverloadSetRootWithInstallArrayIsCalled
        givenRemoveCurrentIsTrue
    {
        // The current root is a validator (set during setUp)
        MockValidator newRoot = new MockValidator();
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(newRoot), moduleData: hex"", internalData: hex""});

        _callSetRoot(ValidationId.wrap(bytes21(0)), packages, hex"");

        // Old root should be uninstalled
        assertFalse(kernel.isModuleInstalled(1, address(rootValidator), ""), "Old root should be uninstalled");

        // New root should be installed and active
        assertTrue(kernel.isModuleInstalled(1, address(newRoot), ""), "New root should be installed");
        assertTrue(
            kernel.validationInfo(validatorToIdentifier(IValidator(address(newRoot)))).installed,
            "New validator should be root"
        );
    }

    modifier givenTheCurrentRootIsAPERMISSION() {
        _currentRootIsPermission = true;
        _;
    }

    function test_GivenUninstallDataHasIncorrectLength()
        external
        whenCallerIsEntryPointOrSelfSetRoot
        givenTheOverloadSetRootWithInstallArrayIsCalled
        givenRemoveCurrentIsTrue
        givenTheCurrentRootIsAPERMISSION
    {
        // it should revert with InvalidDataLength error

        // First set a permission as root
        PermissionId testPermId = PermissionId.wrap(bytes4(keccak256("testIncorrectLen")));
        MockPolicy mockPolicy = new MockPolicy();
        MockSigner mockSigner = new MockSigner();
        kernel.installModule(5, address(mockPolicy), abi.encode(hex"", abi.encodePacked(testPermId)));
        kernel.installModule(6, address(mockSigner), abi.encode(hex"", abi.encodePacked(testPermId)));
        _setPermissionRootIfNeeded(testPermId);

        // Try to replace with new root but with incorrect uninstall data length
        MockValidator newRoot = new MockValidator();
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(newRoot), moduleData: hex"", internalData: hex""});

        // Incorrect uninstall data - should have 2 elements (1 for policy, 1 for signer)
        vm.expectRevert(InvalidDataLength.selector);
        _callSetRoot(ValidationId.wrap(bytes21(0)), packages, _buildPermissionUninstallData());
    }

    modifier givenUninstallDataHasCorrectLength() {
        _uninstallDataCorrectLength = true;
        _;
    }

    function test_GivenPoliciesAreNotUninstalledInReverseOrder()
        external
        whenCallerIsEntryPointOrSelfSetRoot
        givenTheOverloadSetRootWithInstallArrayIsCalled
        givenRemoveCurrentIsTrue
        givenTheCurrentRootIsAPERMISSION
        givenUninstallDataHasCorrectLength
    {
        // it should revert with InvalidPermissionUninstallOrder error
        // Note: setRoot always uninstalls in reverse order internally, so we test
        // the order enforcement by directly calling uninstallModule with wrong order

        // First set up a permission with multiple policies
        MockPolicy mockPolicy1 = new MockPolicy();
        MockPolicy mockPolicy2 = new MockPolicy();
        MockSigner mockSigner = new MockSigner();
        PermissionId testPermId = PermissionId.wrap(bytes4(keccak256("testWrongOrder")));

        // Install policies in order: policy1, policy2, signer
        kernel.installModule(5, address(mockPolicy1), abi.encode(hex"", abi.encodePacked(testPermId)));
        kernel.installModule(5, address(mockPolicy2), abi.encode(hex"", abi.encodePacked(testPermId)));
        kernel.installModule(6, address(mockSigner), abi.encode(hex"", abi.encodePacked(testPermId)));

        // Try to uninstall policy1 first (wrong order - policy2 should be uninstalled first)
        // Policies are stored as [policy1, policy2], so policy2 (last) must be uninstalled first
        vm.expectRevert(InvalidPermissionUninstallOrder.selector);
        kernel.uninstallModule(5, address(mockPolicy1), abi.encode(hex"", abi.encodePacked(testPermId)));
    }

    function test_GivenPoliciesAreUninstalledInReverseOrder()
        external
        whenCallerIsEntryPointOrSelfSetRoot
        givenTheOverloadSetRootWithInstallArrayIsCalled
        givenRemoveCurrentIsTrue
        givenTheCurrentRootIsAPERMISSION
        givenUninstallDataHasCorrectLength
    {
        // it should uninstall permission and set new root

        // First set a permission as root with multiple policies
        MockPolicy mockPolicy1 = new MockPolicy();
        MockPolicy mockPolicy2 = new MockPolicy();
        MockSigner mockSigner = new MockSigner();
        PermissionId testPermId = PermissionId.wrap(bytes4(keccak256("testReverseOrder")));

        // Install policies in order: policy1, policy2, signer
        kernel.installModule(5, address(mockPolicy1), abi.encode(hex"", abi.encodePacked(testPermId)));
        kernel.installModule(5, address(mockPolicy2), abi.encode(hex"", abi.encodePacked(testPermId)));
        kernel.installModule(6, address(mockSigner), abi.encode(hex"", abi.encodePacked(testPermId)));
        _setPermissionRootIfNeeded(testPermId);

        // Replace with new root
        MockValidator newRoot = new MockValidator();
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(newRoot), moduleData: hex"", internalData: hex""});

        // Correct uninstall order - policies in reverse order (policy2, policy1, signer)
        bytes[] memory correctOrderData = new bytes[](_uninstallDataCorrectLength ? 3 : 1);
        correctOrderData[0] = hex""; // Policy2 uninstall data (last installed policy first)
        if (_uninstallDataCorrectLength) {
            correctOrderData[1] = hex""; // Policy1 uninstall data
            correctOrderData[2] = hex""; // Signer uninstall data
        }

        _callSetRoot(ValidationId.wrap(bytes21(0)), packages, abi.encode(correctOrderData));

        // Verify old permission components are uninstalled
        assertFalse(
            kernel.isModuleInstalled(5, address(mockPolicy1), abi.encodePacked(testPermId)),
            "Policy1 should be uninstalled"
        );
        assertFalse(
            kernel.isModuleInstalled(5, address(mockPolicy2), abi.encodePacked(testPermId)),
            "Policy2 should be uninstalled"
        );
        assertFalse(
            kernel.isModuleInstalled(6, address(mockSigner), abi.encodePacked(testPermId)),
            "Signer should be uninstalled"
        );

        // New root should be installed and active
        assertTrue(kernel.isModuleInstalled(1, address(newRoot), ""), "New root should be installed");
        assertTrue(
            kernel.validationInfo(validatorToIdentifier(IValidator(address(newRoot)))).installed,
            "New validator should be root"
        );
    }

    function test_GivenUninstallDataHasCorrectLength()
        external
        whenCallerIsEntryPointOrSelfSetRoot
        givenTheOverloadSetRootWithInstallArrayIsCalled
        givenRemoveCurrentIsTrue
        givenTheCurrentRootIsAPERMISSION
        givenUninstallDataHasCorrectLength
    {
        // First set a permission as root
        MockPolicy mockPolicy = new MockPolicy();
        MockSigner mockSigner = new MockSigner();
        PermissionId testPermId = PermissionId.wrap(bytes4(keccak256("permRootTest2")));

        kernel.installModule(5, address(mockPolicy), abi.encode(hex"", abi.encodePacked(testPermId)));
        kernel.installModule(6, address(mockSigner), abi.encode(hex"", abi.encodePacked(testPermId)));
        _setPermissionRootIfNeeded(testPermId);

        // Replace with new root with correct uninstall data
        MockValidator newRoot = new MockValidator();
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(newRoot), moduleData: hex"", internalData: hex""});

        // Correct uninstall data - 2 elements (1 for policy, 1 for signer)
        bytes memory uninstallData = _buildPermissionUninstallData();
        _callSetRoot(ValidationId.wrap(bytes21(0)), packages, uninstallData);

        // Old permission components should be uninstalled
        assertFalse(
            kernel.isModuleInstalled(5, address(mockPolicy), abi.encodePacked(testPermId)),
            "Policy should be uninstalled"
        );
        assertFalse(
            kernel.isModuleInstalled(6, address(mockSigner), abi.encodePacked(testPermId)),
            "Signer should be uninstalled"
        );

        // New root should be installed and active
        assertTrue(kernel.isModuleInstalled(1, address(newRoot), ""), "New root should be installed");
    }

    function test_GivenTheCurrentRootIsROOTType()
        external
        whenCallerIsEntryPointOrSelfSetRoot
        givenTheOverloadSetRootWithInstallArrayIsCalled
        givenRemoveCurrentIsTrue
    {
        // This test is for when the root has type 0x00 (ROOT type)
        // In practice, a properly initialized kernel always has a validator or permission as root
        // This case would only occur if the root was manually set to an invalid state
        // We use vm.store to simulate this edge case for coverage

        // VALIDATION_MANAGER_STORAGE_SLOT = 0xded5d420c407eac3c615e6abe13ab4a0bd7173e5045ea543765b46f0df6e260c
        bytes32 validationStorageSlot = 0xded5d420c407eac3c615e6abe13ab4a0bd7173e5045ea543765b46f0df6e260c;

        // Create a malformed root ValidationId with type 0x00 (ROOT type) but non-zero ID
        // ValidationId is bytes21: first byte = type, next 20 bytes = ID
        // type 0x00 = ROOT, 0x01 = VALIDATOR, 0x02 = PERMISSION
        address fakeAddress = makeAddr("malformedRoot");
        bytes21 malformedRoot = bytes21(abi.encodePacked(bytes1(0x00), bytes20(fakeAddress)));

        // Set the root storage directly (first slot in ValidationStorage struct is the root)
        vm.store(address(kernel), validationStorageSlot, bytes32(malformedRoot));

        // Mark vInfo[malformedRoot].installed=true. ValidationInfo packs nonce in
        // the low 4 bytes and installed in the following byte.
        bytes32 vInfoSlot = keccak256(abi.encode(bytes32(malformedRoot), bytes32(uint256(validationStorageSlot) + 1)));
        vm.store(address(kernel), vInfoSlot, bytes32(uint256(1) << 32));

        // Now try to replace root with removeCurrent=true
        MockValidator newRoot = new MockValidator();
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(newRoot), moduleData: hex"", internalData: hex""});

        // Should revert with InvalidRootValidation because current root has type 0x00
        vm.expectRevert(InvalidRootValidation.selector);
        _callSetRoot(ValidationId.wrap(bytes21(0)), packages, hex"");
    }

    function test_GivenTheFirstPackageIsNotAValidatorOrPermissionSetRoot()
        external
        whenCallerIsEntryPointOrSelfSetRoot
        givenTheOverloadSetRootWithInstallArrayIsCalled
    {
        // it should revert with InvalidRootValidation error

        // Try to set root with an executor (moduleType 2) as the first package
        Install[] memory packages = new Install[](1);
        packages[0] = Install({
            moduleType: 2, // Executor type - not valid for root
            module: address(0x1234),
            moduleData: hex"",
            internalData: hex""
        });

        vm.expectRevert(InvalidRootValidation.selector);
        _callSetRoot(ValidationId.wrap(bytes21(0)), packages, hex"");
    }

    function test_GivenTheFirstPackageModuleTypeIsPOLICY()
        external
        whenCallerIsEntryPointOrSelfSetRoot
        givenTheOverloadSetRootWithInstallArrayIsCalled
    {
        // it should derive root from permissionId in internalData
        MockPolicy mockPolicy = new MockPolicy();
        MockSigner mockSigner = new MockSigner();
        PermissionId testPermId = PermissionId.wrap(bytes4(keccak256("policyFirstPkg")));

        Install[] memory packages = new Install[](2);
        packages[0] = Install({
            moduleType: 5, // POLICY
            module: address(mockPolicy),
            moduleData: hex"",
            internalData: abi.encodePacked(testPermId)
        });
        packages[1] = Install({
            moduleType: 6, // SIGNER
            module: address(mockSigner),
            moduleData: hex"",
            internalData: abi.encodePacked(testPermId)
        });

        _callSetRoot(ValidationId.wrap(bytes21(0)), packages, hex"");

        // Root should be set to the permission derived from testPermId
        ValidationId expectedRoot = permissionToIdentifier(testPermId);
        assertTrue(kernel.validationInfo(expectedRoot).installed, "Permission should be installed and set as root");
    }

    function test_GivenTheFirstPackageModuleTypeIsSIGNER()
        external
        whenCallerIsEntryPointOrSelfSetRoot
        givenTheOverloadSetRootWithInstallArrayIsCalled
    {
        // it should derive root from permissionId in internalData
        // A signer-only permission (no policies) can be root
        MockSigner mockSigner = new MockSigner();
        PermissionId testPermId = PermissionId.wrap(bytes4(keccak256("signerFirstPkg")));

        Install[] memory packages = new Install[](1);
        packages[0] = Install({
            moduleType: 6, // SIGNER
            module: address(mockSigner),
            moduleData: hex"",
            internalData: abi.encodePacked(testPermId)
        });

        _callSetRoot(ValidationId.wrap(bytes21(0)), packages, hex"");

        // Root should be set to the permission derived from testPermId
        ValidationId expectedRoot = permissionToIdentifier(testPermId);
        assertTrue(
            kernel.validationInfo(expectedRoot).installed,
            "Permission (signer-only) should be installed and set as root"
        );
    }

    /*//////////////////////////////////////////////////////////////
                            HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _callSetRoot(ValidationId vId, Install[] memory packages, bytes memory uninstallData) internal {
        if (_useInstallArrayOverload) {
            kernel.setRoot(packages, _removeCurrent, uninstallData);
        } else {
            kernel.setRoot(vId);
        }
    }

    function _setPermissionRootIfNeeded(PermissionId testPermId) internal {
        if (_currentRootIsPermission) {
            kernel.setRoot(permissionToIdentifier(testPermId));
        }
    }

    function _buildPermissionUninstallData() internal view returns (bytes memory) {
        if (_uninstallDataCorrectLength) {
            bytes[] memory data = new bytes[](2);
            data[0] = hex"";
            data[1] = hex"";
            return abi.encode(data);
        }
        bytes[] memory badData = new bytes[](1);
        badData[0] = hex"";
        return abi.encode(badData);
    }
}
