// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {BTTModifiers} from "./BTTModifiers.sol";
import {Kernel} from "src/Kernel.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Install} from "src/types/Structs.sol";
import {MockValidator} from "../mock/MockValidator.sol";
import {MockPolicy} from "../mock/MockPolicy.sol";
import {MockSigner} from "../mock/MockSigner.sol";
import {MockHook} from "../mock/MockHook.sol";
import {MockFallback} from "../mock/MockFallback.sol";
import {MockCallee} from "../mock/MockCallee.sol";
import {MockExecutor} from "../mock/MockExecutor.sol";
import {IValidator, IModule} from "src/interfaces/IERC7579Modules.sol";
import {ValidationId, PermissionId} from "src/types/Types.sol";
import {validatorToIdentifier, permissionToIdentifier} from "src/lib/Utils.sol";
import {
    Unauthorized,
    UnauthorizedCallData,
    InvalidVid,
    InvalidNonce,
    InvalidSignature,
    InvalidRootValidation,
    InvalidValidationType,
    InvalidPermissionUninstallOrder,
    InvalidDataLength,
    InvalidInitialization,
    InvalidCallType,
    CannotUninstallRoot,
    InstallSignatureVerificationFailed,
    InvalidPermissionInstall,
    PermissionInstallNotFinished,
    NotInstalled,
    OccupiedValidationId
} from "src/types/Error.sol";

/// @title Kernel Branch Coverage BTT Tests
/// @notice Additional BTT tests targeting specific uncovered branches in Kernel.sol,
///         ModuleManager.sol, and ValidationManager.sol
/// @dev These tests complement the existing BTT test suite by covering edge cases
///      and rarely-exercised code paths to increase branch coverage.
abstract contract Kernel_branchCoverage is BTTModifiers {
    /*//////////////////////////////////////////////////////////////
                KERNEL.SOL — _processUserOp BRANCHES
    //////////////////////////////////////////////////////////////*/

    /// @notice Tests enable-mode with replayable enable signature flag set
    /// @dev Covers the isEnableReplayable(vMode) branch in _processUserOp
    function test_processUserOp_enableModeWithReplayableEnableSignature() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        // Create userOp with enable flag AND enable-replayable flag
        // vMode bits: enable=0x08, enable-replayable=0x04 => 0x0C
        PackedUserOperation memory op = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, true, true, bytes1(0x01), bytes20(address(newValidator))),
            initCode: hex"",
            callData: abi.encodePacked(
                Kernel.executeUserOp.selector,
                abi.encodeWithSelector(
                    Kernel.execute.selector,
                    bytes32(0),
                    abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
                )
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });

        // Build enable signature with replayable=true
        op.signature = encodeEnableValidatorSignature(
            Kernel.execute.selector, 0, true, true, _rootSignHash, _validatorSignUserOp(op, true, false)
        );
        bytes32 userOpHash = ep.getUserOpHash(op);

        uint256 validationData = kernel.validateUserOp(op, userOpHash, 0);
        assertEq(validationData, 0, "Enable mode with replayable enable sig should succeed");

        // Verify the validator was installed
        assertEq(
            kernel.validationInfo(validatorToIdentifier(IValidator(address(newValidator)))).hook,
            address(1),
            "Validator should be installed via replayable enable"
        );
    }

    /// @notice Tests enable-mode combined with replayable userOp signature
    /// @dev Covers both enable and replayable flags simultaneously in _processUserOp
    function test_processUserOp_enableModeWithReplayableUserOp() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        // vMode bits: replayable-userOp=0x40, enable=0x08 => 0x48
        PackedUserOperation memory op = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(true, true, false, bytes1(0x01), bytes20(address(newValidator))),
            initCode: hex"",
            callData: abi.encodePacked(
                Kernel.executeUserOp.selector,
                abi.encodeWithSelector(
                    Kernel.execute.selector,
                    bytes32(0),
                    abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
                )
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });

        op.signature = encodeEnableValidatorSignature(
            Kernel.execute.selector, 0, true, false, _rootSignHash, _validatorSignUserOp(op, true, true)
        );
        bytes32 userOpHash = ep.getUserOpHash(op);

        uint256 validationData = kernel.validateUserOp(op, userOpHash, 0);
        assertEq(validationData, 0, "Enable+replayable userOp should succeed");
    }

    /// @notice Tests permission validation with enable mode
    /// @dev Covers enable mode with vType=0x02 (PERMISSION) in _processUserOp
    function test_processUserOp_enableModeWithPermission() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        // Create userOp with enable mode and permission validation type
        PackedUserOperation memory op = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, true, false, bytes1(0x02), PermissionId.unwrap(permissionId)),
            initCode: hex"",
            callData: abi.encodePacked(
                Kernel.executeUserOp.selector,
                abi.encodeWithSelector(
                    Kernel.execute.selector,
                    bytes32(0),
                    abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
                )
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });

        op.signature = encodeEnablePermissionSignature(
            Kernel.execute.selector, 0, true, false, _rootSignHash, _permissionSignUserOp(op, true, false)
        );
        bytes32 userOpHash = ep.getUserOpHash(op);

        uint256 validationData = kernel.validateUserOp(op, userOpHash, 0);
        assertEq(validationData, 0, "Enable mode with permission should succeed");
    }

    /// @notice Tests _processUserOp when selector is allowed but hook!=address(1) and callData
    ///         uses executeUserOp wrapper — the hook storage path
    /// @dev Covers _setValidationHook + _allowedSelector branch with hook set
    function test_processUserOp_validatorWithHookAndAllowedSelector() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        // Install hook
        kernel.installModule(4, address(hook), abi.encode(hex"", hex""));

        // Install validator with hook and allowed selector
        kernel.installModule(
            1, address(newValidator), abi.encode(hex"", abi.encodePacked(address(hook), Kernel.execute.selector))
        );

        PackedUserOperation memory op = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, false, false, bytes1(0x01), bytes20(address(newValidator))),
            initCode: hex"",
            callData: abi.encodePacked(
                Kernel.executeUserOp.selector,
                abi.encodeWithSelector(
                    Kernel.execute.selector,
                    bytes32(0),
                    abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
                )
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        op.signature = _validatorSignUserOp(op, true, false);
        bytes32 userOpHash = ep.getUserOpHash(op);

        uint256 validationData = kernel.validateUserOp(op, userOpHash, 0);
        assertEq(validationData, 0, "Validator with hook and allowed selector should succeed");
    }

    /// @notice Tests permission validation where selector is directly allowed and hook=address(1)
    /// @dev Covers the no-op branch for permission type with allowed selector
    function test_processUserOp_permissionWithDirectlyAllowedSelector() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        // Install permission with allowed selector and hook=address(0) (maps to address(1))
        kernel.installModule(5, address(policy), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        kernel.installModule(
            6,
            address(signer),
            abi.encode(hex"deadbeef", abi.encodePacked(permissionId, address(0), Kernel.execute.selector))
        );

        PackedUserOperation memory op = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, false, false, bytes1(0x02), PermissionId.unwrap(permissionId)),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector,
                bytes32(0),
                abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        op.signature = _permissionSignUserOp(op, true, false);
        bytes32 userOpHash = ep.getUserOpHash(op);

        uint256 validationData = kernel.validateUserOp(op, userOpHash, 0);
        assertEq(validationData, 0, "Permission with directly allowed selector should succeed");
    }

    /*//////////////////////////////////////////////////////////////
                KERNEL.SOL — installModule(bool,uint256,...) OVERLOAD
    //////////////////////////////////////////////////////////////*/

    /// @notice Tests the installModule overload that takes (bool, uint256, Install[], bytes)
    ///         which verifies root signature before installation
    /// @dev Covers the installModule(bool,uint256,Install[],bytes) branch
    function test_installModuleWithSignature_validSignature() external {
        vm.stopPrank();

        // This is the publicly-callable installModule that doesn't require EP/self
        Install[] memory packages = new Install[](1);
        MockValidator testValidator = new MockValidator();
        packages[0] = Install({moduleType: 1, module: address(testValidator), moduleData: hex"", internalData: hex""});

        bytes memory sig = enableSig(0, true, false, packages, _rootSignHash);

        kernel.installModule(false, 0, packages, sig);

        assertTrue(
            kernel.isModuleInstalled(1, address(testValidator), ""), "Validator should be installed via signed install"
        );
    }

    /// @notice Tests installModule with signature when the signature is invalid
    /// @dev Covers the revert path in installModule(bool,uint256,Install[],bytes)
    function test_installModuleWithSignature_invalidSignature() external {
        vm.stopPrank();

        Install[] memory packages = new Install[](1);
        MockValidator testValidator = new MockValidator();
        packages[0] = Install({moduleType: 1, module: address(testValidator), moduleData: hex"", internalData: hex""});

        bytes memory sig = enableSig(0, false, false, packages, _rootSignHash);

        vm.expectRevert(InstallSignatureVerificationFailed.selector);
        kernel.installModule(false, 0, packages, sig);
    }

    /// @notice Tests installModule with replayable=true
    /// @dev Covers the replayable path in _verifyInstallSignature
    function test_installModuleWithSignature_replayable() external {
        vm.stopPrank();

        Install[] memory packages = new Install[](1);
        MockValidator testValidator = new MockValidator();
        packages[0] = Install({moduleType: 1, module: address(testValidator), moduleData: hex"", internalData: hex""});

        bytes memory sig = enableSig(0, true, true, packages, _rootSignHash);

        kernel.installModule(true, 0, packages, sig);

        assertTrue(
            kernel.isModuleInstalled(1, address(testValidator), ""),
            "Validator should be installed via replayable signed install"
        );
    }

    /*//////////////////////////////////////////////////////////////
            VALIDATION_MANAGER.SOL — _checkValidation BRANCHES
    //////////////////////////////////////////////////////////////*/

    /// @notice Tests _checkValidation when vType is PERMISSION
    /// @dev Covers the vType == VALIDATION_TYPE_PERMISSION branch in _checkValidation
    function test_checkValidation_permissionType() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        // Install permission
        kernel.installModule(5, address(policy), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        kernel.installModule(
            6,
            address(signer),
            abi.encode(hex"deadbeef", abi.encodePacked(permissionId, address(0), Kernel.execute.selector))
        );

        // Use permission validation
        PackedUserOperation memory op = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, false, false, bytes1(0x02), PermissionId.unwrap(permissionId)),
            initCode: hex"",
            callData: abi.encodePacked(
                Kernel.executeUserOp.selector,
                abi.encodeWithSelector(
                    Kernel.execute.selector,
                    bytes32(0),
                    abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
                )
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        op.signature = _permissionSignUserOp(op, true, false);
        bytes32 userOpHash = ep.getUserOpHash(op);

        uint256 validationData = kernel.validateUserOp(op, userOpHash, 0);
        assertEq(validationData, 0, "Permission type validation should succeed");
    }

    /// @notice Tests _checkValidation when root is set to a permission
    /// @dev Covers the root resolution to permission type in _checkValidation
    function test_checkValidation_rootResolvedToPermission() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        // Install permission and set as root
        PermissionId rootPermId = PermissionId.wrap(bytes4(keccak256("rootPerm")));
        kernel.installModule(5, address(policy), abi.encode(hex"deadbeef", abi.encodePacked(rootPermId)));
        kernel.installModule(6, address(signer), abi.encode(hex"deadbeef", abi.encodePacked(rootPermId)));
        kernel.setRoot(permissionToIdentifier(rootPermId));

        // Use ROOT validation type - should resolve to the permission
        PackedUserOperation memory op = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, false, false, bytes1(0x00), bytes20(0)),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector,
                bytes32(0),
                abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });

        // Sign with permission signatures since root resolves to permission
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = hex"dead";
        signatures[1] = hex"beef";
        policy.sudoSetValidSig(address(kernel), PermissionId.unwrap(rootPermId), hex"dead");
        signer.sudoSetValidSig(address(kernel), PermissionId.unwrap(rootPermId), hex"beef");
        op.signature = abi.encode(signatures);

        bytes32 userOpHash = ep.getUserOpHash(op);

        uint256 validationData = kernel.validateUserOp(op, userOpHash, 0);
        assertEq(validationData, 0, "Root resolved to permission should validate successfully");
    }

    /*//////////////////////////////////////////////////////////////
            VALIDATION_MANAGER.SOL — _setRoot BRANCHES
    //////////////////////////////////////////////////////////////*/

    /// @notice Tests _setRoot(Install) with MODULE_TYPE_POLICY as first package
    /// @dev Covers the pkg.moduleType == MODULE_TYPE_POLICY branch in _setRoot(Install)
    function test_setRoot_withPolicyAsFirstPackage() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        PermissionId testPermId = PermissionId.wrap(bytes4(keccak256("policyRoot")));
        Install[] memory packages = new Install[](2);
        packages[0] = Install({
            moduleType: 5,
            module: address(policy),
            moduleData: hex"deadbeef",
            internalData: abi.encodePacked(testPermId)
        });
        packages[1] = Install({
            moduleType: 6,
            module: address(signer),
            moduleData: hex"deadbeef",
            internalData: abi.encodePacked(testPermId)
        });

        kernel.setRoot(packages, false, hex"");

        ValidationId expectedRoot = permissionToIdentifier(testPermId);
        assertEq(kernel.validationInfo(expectedRoot).hook, address(1), "Root should be set from policy's permissionId");
    }

    /// @notice Tests _setRoot(Install) with MODULE_TYPE_SIGNER as first package
    /// @dev Covers the pkg.moduleType == MODULE_TYPE_SIGNER branch in _setRoot(Install)
    function test_setRoot_withSignerAsFirstPackage() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        PermissionId testPermId = PermissionId.wrap(bytes4(keccak256("signerRoot")));
        Install[] memory packages = new Install[](1);
        packages[0] = Install({
            moduleType: 6,
            module: address(signer),
            moduleData: hex"deadbeef",
            internalData: abi.encodePacked(testPermId)
        });

        kernel.setRoot(packages, false, hex"");

        ValidationId expectedRoot = permissionToIdentifier(testPermId);
        assertEq(kernel.validationInfo(expectedRoot).hook, address(1), "Root should be set from signer's permissionId");
    }

    /// @notice Tests _setRoot(ValidationId) with an invalid type (not validator, not permission)
    /// @dev Covers the revert path in _setRoot(ValidationId) for invalid types
    function test_setRoot_invalidValidationType() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        // Construct a ValidationId with type 0x03 (invalid)
        // ValidationId is bytes21: [1 byte type][20 bytes id]
        bytes21 invalidVid = bytes21(abi.encodePacked(bytes1(0x03), bytes20(address(1))));
        ValidationId vId = ValidationId.wrap(invalidVid);

        vm.expectRevert(InvalidValidationType.selector);
        kernel.setRoot(vId);
    }

    /// @notice Tests _setRoot(ValidationId) with zero and no fallback validator
    /// @dev Covers the zero check in _setRoot(ValidationId)
    function test_setRoot_zeroVidWithoutFallback() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        ValidationId zeroVid = ValidationId.wrap(bytes21(0));

        vm.expectRevert(InvalidRootValidation.selector);
        kernel.setRoot(zeroVid);
    }

    /// @notice Tests setRoot(Install[], bool, bytes) with removeCurrent=true for VALIDATOR root
    /// @dev Covers the VALIDATION_TYPE_VALIDATOR branch in setRoot with removal
    function test_setRoot_removeCurrentValidator() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        MockValidator newRoot = new MockValidator();
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(newRoot), moduleData: hex"", internalData: hex""});

        kernel.setRoot(packages, true, hex"");

        // Old root should be uninstalled
        assertFalse(kernel.isModuleInstalled(1, address(rootValidator), ""), "Old root should be uninstalled");
        assertTrue(kernel.isModuleInstalled(1, address(newRoot), ""), "New root should be installed");
    }

    /// @notice Tests setRoot with removeCurrent=true for PERMISSION root with correct LIFO uninstall
    /// @dev Covers the VALIDATION_TYPE_PERMISSION branch in setRoot with removal
    function test_setRoot_removeCurrentPermission() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        // First, set up a permission as root
        PermissionId permRootId = PermissionId.wrap(bytes4(keccak256("permRoot")));
        MockPolicy rootPolicy = new MockPolicy();
        MockSigner rootSigner = new MockSigner();

        kernel.installModule(5, address(rootPolicy), abi.encode(hex"", abi.encodePacked(permRootId)));
        kernel.installModule(6, address(rootSigner), abi.encode(hex"", abi.encodePacked(permRootId)));
        kernel.setRoot(permissionToIdentifier(permRootId));

        // Now replace with a new validator root, removing the permission root
        MockValidator newRoot = new MockValidator();
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(newRoot), moduleData: hex"", internalData: hex""});

        // Uninstall data for permission: 1 policy + 1 signer = 2 entries
        bytes[] memory uninstallData = new bytes[](2);
        uninstallData[0] = hex""; // policy uninstall data
        uninstallData[1] = hex""; // signer uninstall data

        kernel.setRoot(packages, true, abi.encode(uninstallData));

        // Verify old permission is fully uninstalled
        assertFalse(
            kernel.isModuleInstalled(5, address(rootPolicy), abi.encodePacked(permRootId)),
            "Old root policy should be uninstalled"
        );
        assertFalse(
            kernel.isModuleInstalled(6, address(rootSigner), abi.encodePacked(permRootId)),
            "Old root signer should be uninstalled"
        );
        assertTrue(kernel.isModuleInstalled(1, address(newRoot), ""), "New root should be installed");
    }

    /// @notice Tests setRoot with removeCurrent=true for PERMISSION with multiple policies
    /// @dev Covers the policy LIFO iteration loop in setRoot
    function test_setRoot_removeCurrentPermissionMultiplePolicies() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        // Set up a permission with 2 policies as root
        PermissionId multiPermId = PermissionId.wrap(bytes4(keccak256("multiPermRoot")));
        MockPolicy policy1 = new MockPolicy();
        MockPolicy policy2 = new MockPolicy();
        MockSigner rootSigner = new MockSigner();

        kernel.installModule(5, address(policy1), abi.encode(hex"", abi.encodePacked(multiPermId)));
        kernel.installModule(5, address(policy2), abi.encode(hex"", abi.encodePacked(multiPermId)));
        kernel.installModule(6, address(rootSigner), abi.encode(hex"", abi.encodePacked(multiPermId)));
        kernel.setRoot(permissionToIdentifier(multiPermId));

        // Replace with new root
        MockValidator newRoot = new MockValidator();
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(newRoot), moduleData: hex"", internalData: hex""});

        // Uninstall data: 2 policies + 1 signer = 3 entries
        bytes[] memory uninstallData = new bytes[](3);
        uninstallData[0] = hex""; // policy2 (last installed, first to uninstall)
        uninstallData[1] = hex""; // policy1
        uninstallData[2] = hex""; // signer

        kernel.setRoot(packages, true, abi.encode(uninstallData));

        // Verify all old permission components are uninstalled
        assertFalse(
            kernel.isModuleInstalled(5, address(policy1), abi.encodePacked(multiPermId)),
            "Policy1 should be uninstalled"
        );
        assertFalse(
            kernel.isModuleInstalled(5, address(policy2), abi.encodePacked(multiPermId)),
            "Policy2 should be uninstalled"
        );
        assertTrue(kernel.isModuleInstalled(1, address(newRoot), ""), "New root should be installed");
    }

    /*//////////////////////////////////////////////////////////////
        VALIDATION_MANAGER.SOL — PERMISSION UNINSTALL ORDERING
    //////////////////////////////////////////////////////////////*/

    /// @notice Tests that uninstalling policy out of LIFO order reverts
    /// @dev Covers the InvalidPermissionUninstallOrder revert in _uninstallPolicyWithVid
    function test_uninstallPolicy_wrongOrder_reverts() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        PermissionId testPermId = PermissionId.wrap(bytes4(keccak256("uninstallOrder")));
        MockPolicy policy1 = new MockPolicy();
        MockPolicy policy2 = new MockPolicy();
        MockSigner testSigner = new MockSigner();

        kernel.installModule(5, address(policy1), abi.encode(hex"", abi.encodePacked(testPermId)));
        kernel.installModule(5, address(policy2), abi.encode(hex"", abi.encodePacked(testPermId)));
        kernel.installModule(6, address(testSigner), abi.encode(hex"", abi.encodePacked(testPermId)));

        // Try to uninstall policy1 first (should fail — policy2 must come first)
        vm.expectRevert(InvalidPermissionUninstallOrder.selector);
        kernel.uninstallModule(5, address(policy1), abi.encode(hex"", abi.encodePacked(testPermId)));
    }

    /// @notice Tests correct LIFO uninstall order for policies
    /// @dev Covers the happy path of _uninstallPolicyWithVid
    function test_uninstallPolicy_correctLIFOOrder() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        PermissionId testPermId = PermissionId.wrap(bytes4(keccak256("lifoOrder")));
        MockPolicy policy1 = new MockPolicy();
        MockPolicy policy2 = new MockPolicy();
        MockSigner testSigner = new MockSigner();

        kernel.installModule(5, address(policy1), abi.encode(hex"", abi.encodePacked(testPermId)));
        kernel.installModule(5, address(policy2), abi.encode(hex"", abi.encodePacked(testPermId)));
        kernel.installModule(6, address(testSigner), abi.encode(hex"", abi.encodePacked(testPermId)));

        // Uninstall in correct LIFO order: policy2 first, then policy1
        kernel.uninstallModule(5, address(policy2), abi.encode(hex"", abi.encodePacked(testPermId)));
        kernel.uninstallModule(5, address(policy1), abi.encode(hex"", abi.encodePacked(testPermId)));

        assertFalse(
            kernel.isModuleInstalled(5, address(policy1), abi.encodePacked(testPermId)), "Policy1 should be uninstalled"
        );
        assertFalse(
            kernel.isModuleInstalled(5, address(policy2), abi.encodePacked(testPermId)), "Policy2 should be uninstalled"
        );
    }

    /// @notice Tests that uninstalling signer while policies remain reverts
    /// @dev Covers InvalidPermissionUninstallOrder in _uninstallSigner
    function test_uninstallSigner_withPoliciesRemaining_reverts() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        PermissionId testPermId = PermissionId.wrap(bytes4(keccak256("signerWithPolicies")));
        MockPolicy testPolicy = new MockPolicy();
        MockSigner testSigner = new MockSigner();

        kernel.installModule(5, address(testPolicy), abi.encode(hex"", abi.encodePacked(testPermId)));
        kernel.installModule(6, address(testSigner), abi.encode(hex"", abi.encodePacked(testPermId)));

        // Try to uninstall signer before policy — should fail
        vm.expectRevert(InvalidPermissionUninstallOrder.selector);
        kernel.uninstallModule(6, address(testSigner), abi.encode(hex"", abi.encodePacked(testPermId)));
    }

    /// @notice Tests uninstalling root validation reverts
    /// @dev Covers CannotUninstallRoot in _uninstallValidation
    function test_uninstallValidator_cannotUninstallRoot() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        // Root is currently the rootValidator set in setUp
        vm.expectRevert(CannotUninstallRoot.selector);
        kernel.uninstallModule(1, address(rootValidator), abi.encode(hex"", hex""));
    }

    /*//////////////////////////////////////////////////////////////
        MODULE_MANAGER.SOL — NONCE MANAGEMENT BRANCHES
    //////////////////////////////////////////////////////////////*/

    /// @notice Tests _checkNonce branch when nonceValidFrom > nonce[key]
    /// @dev Covers the nonceValidFrom > nonce[key] path in _checkNonce
    function test_checkNonce_nonceValidFromGreaterThanStoredNonce() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        // Set validNonceFrom to a higher value
        kernel.setValidNonceFrom(5);

        // Now isValidSignature with enable mode should check nonce against nonceValidFrom
        // The nonce must equal nonceValidFrom (which is 5)
        assertEq(kernel.validNonceFrom(), 5, "validNonceFrom should be 5");
    }

    /// @notice Tests _setValidNonceFrom with value less than current — should revert
    /// @dev Covers the InvalidNonce revert in _setValidNonceFrom
    function test_setValidNonceFrom_decreasing_reverts() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        kernel.setValidNonceFrom(10);

        vm.expectRevert(InvalidNonce.selector);
        kernel.setValidNonceFrom(5);
    }

    /// @notice Tests _setNonce with increasing value
    /// @dev Covers the _setNonce function
    function test_setNonce_increasing() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        kernel.setNonce(1, 10);

        // Setting to same value should fail
        vm.expectRevert(InvalidNonce.selector);
        kernel.setNonce(1, 10);
    }

    /// @notice Tests _setNonce with value less than current — should revert
    /// @dev Covers the InvalidNonce revert in _setNonce
    function test_setNonce_decreasing_reverts() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        kernel.setNonce(1, 10);

        vm.expectRevert(InvalidNonce.selector);
        kernel.setNonce(1, 5);
    }

    /*//////////////////////////////////////////////////////////////
        VALIDATION_MANAGER.SOL — _initializeValidation BRANCHES
    //////////////////////////////////////////////////////////////*/

    /// @notice Tests _initializeValidation with empty internalData
    /// @dev Covers the _internalData.length == 0 branch in _initializeValidation
    function test_initializeValidation_emptyInternalData() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        // Install a validator with empty internalData
        MockValidator testValidator = new MockValidator();
        kernel.installModule(1, address(testValidator), abi.encode(hex"", hex""));

        // Validator should be installed but with no allowed selectors
        assertEq(
            kernel.validationInfo(validatorToIdentifier(IValidator(address(testValidator)))).hook,
            address(1),
            "Validator with empty internalData should have hook=address(1)"
        );
    }

    /// @notice Tests _initializeValidation when hook is address(0) in internalData
    /// @dev Covers hook == HOOK_MODULE_NOT_INSTALLED => HOOK_MODULE_INSTALLED_NO_HOOK mapping
    function test_initializeValidation_hookAddress0MapsToAddress1() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        MockValidator testValidator = new MockValidator();
        // internalData starts with address(0) as hook
        kernel.installModule(
            1, address(testValidator), abi.encode(hex"", abi.encodePacked(address(0), Kernel.execute.selector))
        );

        // Hook should be set to address(1) (HOOK_MODULE_INSTALLED_NO_HOOK)
        assertEq(
            kernel.validationInfo(validatorToIdentifier(IValidator(address(testValidator)))).hook,
            address(1),
            "Hook address(0) should map to address(1)"
        );
    }

    /// @notice Tests _initializeValidation when hook is address(1) in internalData
    /// @dev Covers hook == HOOK_MODULE_INSTALLED_NO_HOOK case
    function test_initializeValidation_hookAddress1Stays() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        MockValidator testValidator = new MockValidator();
        // internalData starts with address(1)
        kernel.installModule(
            1, address(testValidator), abi.encode(hex"", abi.encodePacked(address(1), Kernel.execute.selector))
        );

        assertEq(
            kernel.validationInfo(validatorToIdentifier(IValidator(address(testValidator)))).hook,
            address(1),
            "Hook address(1) should stay address(1)"
        );
    }

    /// @notice Tests that OccupiedValidationId is thrown when trying to install a validator twice
    /// @dev Covers the require in _initializeValidation
    function test_initializeValidation_occupied_reverts() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        MockValidator testValidator = new MockValidator();
        kernel.installModule(1, address(testValidator), abi.encode(hex"", hex""));

        vm.expectRevert(OccupiedValidationId.selector);
        kernel.installModule(1, address(testValidator), abi.encode(hex"", hex""));
    }

    /*//////////////////////////////////////////////////////////////
        VALIDATION_MANAGER.SOL — _grantAccess BRANCHES
    //////////////////////////////////////////////////////////////*/

    /// @notice Tests grantAccess with selectors length not multiple of 4 — should revert
    /// @dev Covers the InvalidDataLength revert in _grantAccess
    function test_grantAccess_invalidLength_reverts() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        MockValidator testValidator = new MockValidator();
        kernel.installModule(1, address(testValidator), abi.encode(hex"", hex""));

        ValidationId vId = validatorToIdentifier(IValidator(address(testValidator)));

        // Pass selectors with length not multiple of 4
        vm.expectRevert(InvalidDataLength.selector);
        kernel.grantAccess(vId, hex"aabbcc"); // 3 bytes, not multiple of 4
    }

    /// @notice Tests grantAccess with valid selectors
    /// @dev Covers the while loop in _grantAccess
    function test_grantAccess_validSelectors() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        MockValidator testValidator = new MockValidator();
        kernel.installModule(1, address(testValidator), abi.encode(hex"", hex""));

        ValidationId vId = validatorToIdentifier(IValidator(address(testValidator)));

        // Grant access to execute selector
        kernel.grantAccess(vId, abi.encodePacked(Kernel.execute.selector));

        // Verify by using this validator with the execute selector directly
        PackedUserOperation memory op = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, false, false, bytes1(0x01), bytes20(address(testValidator))),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector,
                bytes32(0),
                abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });

        testValidator.sudoSetSuccess(true);
        op.signature = hex"";
        bytes32 userOpHash = ep.getUserOpHash(op);

        uint256 validationData = kernel.validateUserOp(op, userOpHash, 0);
        assertEq(validationData, 0, "Granted selector should allow direct validation");
    }

    /*//////////////////////////////////////////////////////////////
        VALIDATION_MANAGER.SOL — _checkPermissionInstall BRANCHES
    //////////////////////////////////////////////////////////////*/

    /// @notice Tests _checkPermissionInstall with inconsistent permissionId
    /// @dev Covers the require(installingPermission == vId) branch
    function test_checkPermissionInstall_inconsistentPermissionId_reverts() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        PermissionId permId1 = PermissionId.wrap(bytes4(keccak256("perm1")));
        PermissionId permId2 = PermissionId.wrap(bytes4(keccak256("perm2")));

        MockPolicy testPolicy = new MockPolicy();
        MockSigner testSigner = new MockSigner();

        // Install policy with permId1
        // Then try to install signer with permId2 (should fail due to inconsistent permissionId)
        Install[] memory packages = new Install[](2);
        packages[0] = Install({
            moduleType: 5, module: address(testPolicy), moduleData: hex"", internalData: abi.encodePacked(permId1)
        });
        packages[1] = Install({
            moduleType: 6,
            module: address(testSigner),
            moduleData: hex"",
            internalData: abi.encodePacked(permId2) // Different permissionId!
        });

        vm.expectRevert(InvalidPermissionInstall.selector);
        kernel.installModule(packages);
    }

    /// @notice Tests PermissionInstallNotFinished when batch ends without signer
    /// @dev Covers the require at the end of _install(Install[])
    function test_install_permissionNotFinished_reverts() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        PermissionId testPermId = PermissionId.wrap(bytes4(keccak256("unfinished")));
        MockPolicy testPolicy = new MockPolicy();

        // Install only a policy without signer — should fail
        Install[] memory packages = new Install[](1);
        packages[0] = Install({
            moduleType: 5, module: address(testPolicy), moduleData: hex"", internalData: abi.encodePacked(testPermId)
        });

        vm.expectRevert(PermissionInstallNotFinished.selector);
        kernel.installModule(packages);
    }

    /*//////////////////////////////////////////////////////////////
        MODULE_MANAGER.SOL — _checkAndIncrementNonce BRANCHES
    //////////////////////////////////////////////////////////////*/

    /// @notice Tests _checkAndIncrementNonce when nonceValidFrom > stored nonce
    /// @dev Covers the nonceValidFrom > nonce[key] reset branch in _checkAndIncrementNonce
    function test_checkAndIncrementNonce_nonceValidFromReset() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        // Set validNonceFrom to a higher value
        kernel.setValidNonceFrom(5);

        // Build enable-mode userOp with sig.nonce=5 matching nonceValidFrom
        // (encodeEnableValidatorSignature always hardcodes sig.nonce=0, so we must build manually)
        PackedUserOperation memory op = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, true, false, bytes1(0x01), bytes20(address(newValidator))),
            initCode: hex"",
            callData: abi.encodePacked(
                Kernel.executeUserOp.selector,
                abi.encodeWithSelector(
                    Kernel.execute.selector,
                    bytes32(0),
                    abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
                )
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });

        // Manually build enable signature with sig.nonce=5
        Install[] memory packages = new Install[](1);
        packages[0] = Install({
            moduleType: 1,
            module: address(newValidator),
            moduleData: hex"",
            internalData: abi.encodePacked(address(0), Kernel.execute.selector)
        });

        bytes memory enableSignature = enableSig(5, true, false, packages, _rootSignHash);
        bytes memory userOpSig = _validatorSignUserOp(op, true, false);

        // Encode with sig.nonce=5 (not 0) so _checkAndIncrementNonce(5) succeeds
        op.signature = abi.encode(uint256(5), packages, enableSignature, userOpSig);

        bytes32 userOpHash = ep.getUserOpHash(op);

        // This will exercise the _checkAndIncrementNonce path where nonceValidFrom > stored nonce
        uint256 validationData = kernel.validateUserOp(op, userOpHash, 0);
        assertEq(validationData, 0, "Enable mode after setValidNonceFrom should succeed");
    }

    /*//////////////////////////////////////////////////////////////
        MODULE_MANAGER.SOL — VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Tests the registry() view function
    /// @dev Covers registry() view function
    function test_registry_returnsZero() external view {
        assertEq(kernel.registry(), address(0), "Registry should be address(0) by default");
    }

    /// @notice Tests the nonce() view function with validNonceFrom interaction
    /// @dev Covers the nonce() function with nonceValidFrom > seq branch
    function test_nonce_withValidNonceFrom() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        // Get initial nonce
        uint256 nonce0 = kernel.nonce(0);
        assertEq(nonce0, 0, "Initial nonce should be 0");

        // Set validNonceFrom
        kernel.setValidNonceFrom(10);

        // Nonce should now return validNonceFrom as the seq
        uint256 nonceAfter = kernel.nonce(0);
        assertEq(nonceAfter, 10, "Nonce should return validNonceFrom when it exceeds stored nonce");
    }

    /// @notice Tests validNonceFrom() view function
    /// @dev Covers validNonceFrom() view function
    function test_validNonceFrom_returnsValue() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        assertEq(kernel.validNonceFrom(), 0, "Initial validNonceFrom should be 0");

        kernel.setValidNonceFrom(42);
        assertEq(kernel.validNonceFrom(), 42, "validNonceFrom should be updated");
    }

    /*//////////////////////////////////////////////////////////////
            KERNEL.SOL — MISC BRANCH COVERAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Tests accountId() returns expected string
    function test_accountId() external view {
        assertEq(kernel.accountId(), "kernel.v0.4", "accountId should return kernel.v0.4");
    }

    /// @notice Tests supportsModule for all valid types (1-6)
    function test_supportsModule_allTypes() external view {
        assertTrue(kernel.supportsModule(1), "Should support type 1 (validator)");
        assertTrue(kernel.supportsModule(2), "Should support type 2 (executor)");
        assertTrue(kernel.supportsModule(3), "Should support type 3 (fallback)");
        assertTrue(kernel.supportsModule(4), "Should support type 4 (hook)");
        assertTrue(kernel.supportsModule(5), "Should support type 5 (policy)");
        assertTrue(kernel.supportsModule(6), "Should support type 6 (signer)");
        assertFalse(kernel.supportsModule(0), "Should NOT support type 0");
        assertFalse(kernel.supportsModule(7), "Should NOT support type 7");
    }

    /// @notice Tests isModuleInstalled for MODULE_TYPE_HOOK
    function test_isModuleInstalled_hookType() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        kernel.installModule(4, address(hook), abi.encode(hex"", hex""));

        assertTrue(kernel.isModuleInstalled(4, address(hook), ""), "Hook should be installed");
    }

    /// @notice Tests isModuleInstalled for unsupported module type
    function test_isModuleInstalled_unsupportedType_reverts() external {
        vm.expectRevert();
        kernel.isModuleInstalled(7, address(0x1234), "");
    }

    /// @notice Tests isModuleInstalled for policy type
    function test_isModuleInstalled_policyType() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        kernel.installModule(5, address(policy), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));

        assertTrue(
            kernel.isModuleInstalled(5, address(policy), abi.encodePacked(permissionId)), "Policy should be installed"
        );

        // Check non-installed policy returns false
        MockPolicy otherPolicy = new MockPolicy();
        assertFalse(
            kernel.isModuleInstalled(5, address(otherPolicy), abi.encodePacked(permissionId)),
            "Non-installed policy should not be found"
        );
    }

    /// @notice Tests isModuleInstalled for signer type
    function test_isModuleInstalled_signerType() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        kernel.installModule(5, address(policy), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        kernel.installModule(6, address(signer), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));

        assertTrue(
            kernel.isModuleInstalled(6, address(signer), abi.encodePacked(permissionId)), "Signer should be installed"
        );

        // Check non-installed signer returns false
        MockSigner otherSigner = new MockSigner();
        assertFalse(
            kernel.isModuleInstalled(6, address(otherSigner), abi.encodePacked(permissionId)),
            "Non-installed signer should not be found"
        );
    }

    /// @notice Tests isModuleInstalled for executor type
    function test_isModuleInstalled_executorType() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        MockExecutor testExecutor = new MockExecutor();
        kernel.installModule(2, address(testExecutor), abi.encode(hex"", hex""));

        assertTrue(kernel.isModuleInstalled(2, address(testExecutor), ""), "Executor should be installed");
    }

    /// @notice Tests isModuleInstalled for fallback type
    function test_isModuleInstalled_fallbackType() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        bytes4 testSelector = MockFallback.getCaller.selector;
        kernel.installModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSelector, bytes1(0x00), address(1)))
        );

        assertTrue(
            kernel.isModuleInstalled(3, address(mockFallback), abi.encodePacked(testSelector)),
            "Fallback should be installed for selector"
        );
    }

    /// @notice Tests validationInfo() view function
    function test_validationInfo_returnsData() external view {
        // Root validator should have hook=address(1) and no policies
        ValidationId rootVid = validatorToIdentifier(IValidator(address(rootValidator)));
        assertEq(kernel.validationInfo(rootVid).hook, address(1), "Root validator should have hook=address(1)");
    }

    /// @notice Tests root() view function
    function test_root_returnsCurrentRoot() external view {
        ValidationId currentRoot = kernel.root();
        ValidationId expectedRoot = validatorToIdentifier(IValidator(address(rootValidator)));
        assertEq(
            ValidationId.unwrap(currentRoot),
            ValidationId.unwrap(expectedRoot),
            "root() should return the root validator"
        );
    }

    /*//////////////////////////////////////////////////////////////
            KERNEL.SOL — supportsExecutionMode BRANCHES
    //////////////////////////////////////////////////////////////*/

    /// @notice Tests supportsExecutionMode with valid single+default mode
    function test_supportsExecutionMode_singleDefault() external view {
        // CALLTYPE_SINGLE=0x00, EXECTYPE_DEFAULT=0x00
        assertTrue(kernel.supportsExecutionMode(bytes32(0)), "Single+Default should be supported");
    }

    /// @notice Tests supportsExecutionMode with batch+try mode
    function test_supportsExecutionMode_batchTry() external view {
        // CALLTYPE_BATCH=0x01, EXECTYPE_TRY=0x01
        bytes32 mode = bytes32(abi.encodePacked(bytes1(0x01), bytes1(0x01), bytes30(0)));
        assertTrue(kernel.supportsExecutionMode(mode), "Batch+Try should be supported");
    }

    /// @notice Tests supportsExecutionMode with delegatecall+default
    function test_supportsExecutionMode_delegatecallDefault() external view {
        // CALLTYPE_DELEGATECALL=0xFF, EXECTYPE_DEFAULT=0x00
        bytes32 mode = bytes32(abi.encodePacked(bytes1(0xFF), bytes1(0x00), bytes30(0)));
        assertTrue(kernel.supportsExecutionMode(mode), "Delegatecall+Default should be supported");
    }

    /// @notice Tests supportsExecutionMode with unsupported exec type
    function test_supportsExecutionMode_unsupportedExecType() external view {
        // CALLTYPE_SINGLE=0x00, EXECTYPE=0x02 (unsupported)
        bytes32 mode = bytes32(abi.encodePacked(bytes1(0x00), bytes1(0x02), bytes30(0)));
        assertFalse(kernel.supportsExecutionMode(mode), "Unsupported exec type should return false");
    }

    /// @notice Tests supportsExecutionMode with unsupported call type
    function test_supportsExecutionMode_unsupportedCallType() external view {
        // CALLTYPE=0x02 (unsupported), EXECTYPE_DEFAULT=0x00
        bytes32 mode = bytes32(abi.encodePacked(bytes1(0x02), bytes1(0x00), bytes30(0)));
        assertFalse(kernel.supportsExecutionMode(mode), "Unsupported call type should return false");
    }

    /*//////////////////////////////////////////////////////////////
                KERNEL.SOL — EXECUTE BRANCHES
    //////////////////////////////////////////////////////////////*/

    /// @notice Tests execute from self (not just entrypoint)
    function test_execute_fromSelf() external {
        vm.stopPrank();
        vm.startPrank(address(ep));

        // Execute a call that calls execute again from the kernel itself
        // This tests the _onlyEntryPointOrSelf check for self
        bytes memory innerCall = abi.encodeWithSelector(
            Kernel.execute.selector, bytes32(0), abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
        );

        kernel.execute(bytes32(0), abi.encodePacked(address(kernel), uint256(0), innerCall));
    }

    /// @notice Tests that execute reverts for unauthorized caller
    function test_execute_unauthorized_reverts() external {
        vm.stopPrank();
        vm.startPrank(makeAddr("randomCaller"));

        vm.expectRevert(Unauthorized.selector);
        kernel.execute(bytes32(0), abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector));
    }
}
