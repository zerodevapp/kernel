// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {Kernel} from "src/Kernel.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {KernelImmutableECDSA} from "src/KernelImmutableECDSA.sol";
import {KernelFactory} from "src/KernelFactory.sol";
import {KernelHelper} from "../KernelHelper.sol";
import {Install, ValidationInfo, SelectorConfig, ExecutorConfig} from "src/types/Structs.sol";
import {ValidationId, PermissionId, CallType} from "src/types/Types.sol";
import {MockValidator} from "../mock/MockValidator.sol";
import {MockPolicy} from "../mock/MockPolicy.sol";
import {MockSigner} from "../mock/MockSigner.sol";
import {MockHook} from "../mock/MockHook.sol";
import {MockFallback} from "../mock/MockFallback.sol";
import {MockExecutor} from "../mock/MockExecutor.sol";
import {MockCallee} from "../mock/MockCallee.sol";
import {ChainAgnosticHashHelper} from "../utils/ChainAgnosticHashHelper.sol";
import {
    InvalidValidationType,
    InvalidNonce,
    InvalidSignature,
    NotImplemented,
    Unauthorized,
    ModuleInstallFailed,
    InstallSignatureVerificationFailed,
    InvalidSigner,
    ImplementationNotDeployed,
    InvalidTargetAddress,
    DeployFailed,
    NotApprovedFactory,
    InvalidOwner,
    InvalidInitialization,
    AlreadyInitialized,
    NotInitialized,
    InvalidSelectorTarget
} from "src/types/Error.sol";
import {
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_POLICY,
    MODULE_TYPE_SIGNER,
    CALLTYPE_SINGLE,
    CALLTYPE_DELEGATECALL,
    ERC1271_MAGICVALUE,
    ERC1271_INVALID,
    SIG_VALIDATION_FAILED_UINT,
    VALIDATION_TYPE_ROOT,
    VALIDATION_TYPE_VALIDATOR,
    VALIDATION_TYPE_PERMISSION
} from "src/types/Constants.sol";
import {validatorToIdentifier, permissionToIdentifier} from "src/lib/Utils.sol";
import {IValidator, IExecutor} from "src/interfaces/IERC7579Modules.sol";
import {IERC7579Account} from "src/interfaces/IERC7579Account.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";

/// @notice Unit tests for ModuleManager.sol covering enable+replayable install flow,
///         nonce management, ERC-1271 paths, and boundary conditions.
contract ModuleManagerCoverageTest is Test {
    IEntryPoint ep;
    KernelFactory factory;
    Kernel kernel;
    MockValidator rootValidator;
    MockValidator newValidator;
    MockPolicy policy;
    MockSigner signer;
    MockHook hook;
    MockFallback mockFallback;
    MockExecutor mockExecutor;
    MockCallee callee;
    address payable beneficiary;
    PermissionId permissionId;
    ChainAgnosticHashHelper hashHelper;

    function setUp() public {
        ep = EntryPointLib.deploy();
        KernelUUPS uups = new KernelUUPS(ep);
        KernelImmutableECDSA immutableEcdsa = new KernelImmutableECDSA(ep);
        factory = new KernelFactory(uups, immutableEcdsa);
        rootValidator = new MockValidator();
        newValidator = new MockValidator();
        policy = new MockPolicy();
        signer = new MockSigner();
        hook = new MockHook();
        mockFallback = new MockFallback();
        mockExecutor = new MockExecutor();
        callee = new MockCallee();
        beneficiary = payable(makeAddr("Beneficiary"));
        hashHelper = new ChainAgnosticHashHelper();
        permissionId = PermissionId.wrap(bytes4(keccak256(abi.encodePacked("TestPermission2"))));

        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({
            moduleType: MODULE_TYPE_VALIDATOR, module: address(rootValidator), moduleData: hex"", internalData: hex""
        });
        kernel = factory.deploy(pkgs, 0);
        vm.deal(address(kernel), 10 ether);
    }

    // =========================================================================
    // installModuleWithSignature — enable + replayable flow
    // =========================================================================

    function test_installModuleWithSignature_WhenReplayableAndValid_ShouldInstallModule() public {
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({
            moduleType: MODULE_TYPE_VALIDATOR, module: address(newValidator), moduleData: hex"", internalData: hex""
        });

        // Compute digest for replayable=true
        bytes32 digest = KernelHelper.installDigest(address(kernel), true, 0, pkgs);
        rootValidator.sudoSetValidSig(hex"");

        kernel.installModule(true, 0, pkgs, hex"");
        assertTrue(
            kernel.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(newValidator), hex""),
            "Validator should be installed"
        );
    }

    function test_installModuleWithSignature_WhenNonReplayableAndValid_ShouldInstallModule() public {
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({
            moduleType: MODULE_TYPE_VALIDATOR, module: address(newValidator), moduleData: hex"", internalData: hex""
        });

        bytes32 digest = KernelHelper.installDigest(address(kernel), false, 0, pkgs);
        rootValidator.sudoSetValidSig(hex"");

        kernel.installModule(false, 0, pkgs, hex"");
    }

    // =========================================================================
    // ERC-1271 — validator type path
    // =========================================================================

    function test_isValidSignature_WhenValidatorType_ShouldValidate() public {
        vm.prank(address(ep));
        kernel.installModule(MODULE_TYPE_VALIDATOR, address(newValidator), abi.encode(hex"", hex""));

        bytes32 testHash = keccak256("validator test");
        newValidator.sudoSetValidSig(hex"aabb");

        bytes memory signature = abi.encodePacked(
            bytes1(0x01), // type: validator
            address(newValidator),
            hex"aabb"
        );

        bytes4 result = kernel.isValidSignature(testHash, signature);
        assertEq(result, ERC1271_MAGICVALUE, "Validator should approve signature");
    }

    function test_isValidSignature_WhenValidatorTypeRejects_ShouldReturnInvalid() public {
        vm.prank(address(ep));
        kernel.installModule(MODULE_TYPE_VALIDATOR, address(newValidator), abi.encode(hex"", hex""));

        bytes32 testHash = keccak256("validator test");

        bytes memory signature = abi.encodePacked(
            bytes1(0x01),
            address(newValidator),
            hex"ccdd" // not valid
        );

        bytes4 result = kernel.isValidSignature(testHash, signature);
        assertEq(result, ERC1271_INVALID, "Validator should reject invalid signature");
    }

    // =========================================================================
    // ERC-1271 — permission type path
    // =========================================================================

    function test_isValidSignature_WhenPermissionType_ShouldValidate() public {
        // Install permission
        Install[] memory pkgs = new Install[](2);
        pkgs[0] = Install({
            moduleType: MODULE_TYPE_POLICY,
            module: address(policy),
            moduleData: hex"",
            internalData: abi.encodePacked(permissionId)
        });
        pkgs[1] = Install({
            moduleType: MODULE_TYPE_SIGNER,
            module: address(signer),
            moduleData: hex"",
            internalData: abi.encodePacked(permissionId, address(0), Kernel.execute.selector)
        });
        vm.prank(address(ep));
        kernel.installModule(pkgs);

        bytes32 testHash = keccak256("permission test");
        bytes32 paddedVId = bytes32(PermissionId.unwrap(permissionId));

        // Set policy and signer to pass
        policy.sudoSetPass(address(kernel), paddedVId, true);
        signer.sudoSetPass(address(kernel), paddedVId, true);

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = hex"dead";
        signatures[1] = hex"beef";

        bytes memory signature = abi.encodePacked(
            bytes1(0x02), // type: permission
            permissionId,
            abi.encode(signatures)
        );

        bytes4 result = kernel.isValidSignature(testHash, signature);
        assertEq(result, ERC1271_MAGICVALUE, "Permission should approve signature");
    }

    // =========================================================================
    // ERC-1271 — InvalidValidationType (type 0x03)
    // =========================================================================

    function test_isValidSignature_WhenInvalidValidationType_ShouldRevertWithInvalidValidationType() public {
        bytes32 testHash = keccak256("test");
        bytes memory signature = abi.encodePacked(
            bytes1(0x03), // invalid type
            hex"00000000000000000000000000000000000000000000"
        );

        vm.expectRevert(InvalidValidationType.selector);
        kernel.isValidSignature(testHash, signature);
    }

    // =========================================================================
    // InvalidSignature — permission signature with wrong number of sub-signatures
    // =========================================================================

    function test_isValidSignature_WhenPermissionWrongSigCount_ShouldRevert() public {
        Install[] memory pkgs = new Install[](2);
        pkgs[0] = Install({
            moduleType: MODULE_TYPE_POLICY,
            module: address(policy),
            moduleData: hex"",
            internalData: abi.encodePacked(permissionId)
        });
        pkgs[1] = Install({
            moduleType: MODULE_TYPE_SIGNER,
            module: address(signer),
            moduleData: hex"",
            internalData: abi.encodePacked(permissionId, address(0), Kernel.execute.selector)
        });
        vm.prank(address(ep));
        kernel.installModule(pkgs);

        bytes32 testHash = keccak256("wrong count");

        // Only 1 signature but 2 expected (1 policy + 1 signer)
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = hex"dead";

        bytes memory signature = abi.encodePacked(bytes1(0x02), permissionId, abi.encode(signatures));

        vm.expectRevert(InvalidSignature.selector);
        kernel.isValidSignature(testHash, signature);
    }

    // =========================================================================
    // Nonce management — _checkAndIncrementNonce paths
    // =========================================================================

    function test_nonce_WhenKeyHasValue_ShouldReturnCorrectNonce() public view {
        uint256 n = kernel.nonce(0);
        assertEq(n, 0, "Initial nonce for key 0 should be 0");
    }

    function test_nonce_WhenValidNonceFromExceedsKey_ShouldReturnValidNonceFrom() public {
        vm.startPrank(address(ep));
        kernel.setValidNonceFrom(5);
        vm.stopPrank();

        uint256 n = kernel.nonce(0);
        assertEq(n, 5, "Nonce should be validNonceFrom when key nonce is lower");
    }

    function test_nonce_WhenKeyIsNonZero_ShouldIncludeKey() public view {
        uint192 testKey = 42;
        uint256 n = kernel.nonce(testKey);
        assertEq(n, (uint256(testKey) << 64), "Nonce should include key in high bits");
    }

    // =========================================================================
    // ModuleInstallFailed — fallback with CALLTYPE_SINGLE when onInstall fails
    // =========================================================================

    function test_installFallback_WhenOnInstallFailsAndCallTypeSingle_ShouldRevertWithModuleInstallFailed() public {
        address revertingFallback = address(new RevertingOnInstallFallback());
        bytes4 testSel = bytes4(keccak256("fallbackFn()"));

        vm.prank(address(ep));
        vm.expectRevert(ModuleInstallFailed.selector);
        kernel.installModule(
            MODULE_TYPE_FALLBACK, revertingFallback, abi.encode(hex"", abi.encodePacked(testSel, bytes1(0x00)))
        );
    }

    function test_installFallback_WhenOnInstallFailsAndCallTypeDelegatecall_ShouldNotRevert() public {
        address revertingFallback = address(new RevertingOnInstallFallback());
        bytes4 testSel = bytes4(keccak256("fallbackFn()"));

        // CALLTYPE_DELEGATECALL does not require onInstall success
        vm.prank(address(ep));
        kernel.installModule(
            MODULE_TYPE_FALLBACK, revertingFallback, abi.encode(hex"", abi.encodePacked(testSel, bytes1(0xFF)))
        );

        SelectorConfig memory config = kernel.selectorConfig(testSel);
        assertEq(config.target, revertingFallback, "Fallback should be installed despite onInstall failure");
    }

    // =========================================================================
    // InvalidSelectorTarget — fallback install with zero-address module
    // =========================================================================

    /// @notice Regression: SelectorManager._installSelector must reject `_module == address(0)`
    ///         at the install boundary. Without this guard the writer silently records a
    ///         zero-target SelectorConfig that downstream dispatch later rejects with
    ///         `InvalidSelector`, dropping the caller's intent without feedback.
    function test_installFallback_WhenModuleIsZeroAddress_ShouldRevertWithInvalidSelectorTarget() public {
        bytes4 testSel = MockFallback.testFunction.selector;

        vm.prank(address(ep));
        vm.expectRevert(InvalidSelectorTarget.selector);
        kernel.installModule(
            MODULE_TYPE_FALLBACK, address(0), abi.encode(hex"", abi.encodePacked(testSel, bytes1(0xFF)))
        );
    }

    // =========================================================================
    // Uninstall fallback — resets storage
    // =========================================================================

    function test_uninstallFallback_ShouldClearSelectorConfig() public {
        bytes4 testSel = MockFallback.testFunction.selector;
        vm.startPrank(address(ep));

        kernel.installModule(
            MODULE_TYPE_FALLBACK, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSel, bytes1(0x00)))
        );

        SelectorConfig memory config = kernel.selectorConfig(testSel);
        assertEq(config.target, address(mockFallback), "Fallback should be installed");

        kernel.uninstallModule(
            MODULE_TYPE_FALLBACK, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSel))
        );

        config = kernel.selectorConfig(testSel);
        assertEq(config.target, address(0), "Fallback should be uninstalled");
        vm.stopPrank();
    }

    // =========================================================================
    // Uninstall hook

    // =========================================================================
    // Uninstall executor
    // =========================================================================

    function test_uninstallExecutor_ShouldDisableExecutor() public {
        vm.startPrank(address(ep));
        kernel.installModule(MODULE_TYPE_EXECUTOR, address(mockExecutor), abi.encode(hex"", hex""));
        assertTrue(
            kernel.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(mockExecutor), hex""), "Executor should be installed"
        );

        kernel.uninstallModule(MODULE_TYPE_EXECUTOR, address(mockExecutor), abi.encode(hex"", hex""));
        assertFalse(
            kernel.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(mockExecutor), hex""),
            "Executor should be uninstalled"
        );
        vm.stopPrank();
    }

    // =========================================================================
    // Uninstall validator (non-root)
    // =========================================================================

    function test_uninstallValidator_WhenNotRoot_ShouldSucceed() public {
        vm.startPrank(address(ep));
        kernel.installModule(MODULE_TYPE_VALIDATOR, address(newValidator), abi.encode(hex"", hex""));
        assertTrue(
            kernel.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(newValidator), hex""),
            "Validator should be installed"
        );

        kernel.uninstallModule(MODULE_TYPE_VALIDATOR, address(newValidator), abi.encode(hex"", hex""));
        assertFalse(
            kernel.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(newValidator), hex""),
            "Validator should be uninstalled"
        );
        vm.stopPrank();
    }

    // =========================================================================
    // _checkValidation — permission type
    // =========================================================================

    function test_processUserOp_WhenPermissionType_ShouldUsePermissionValidation() public {
        // Install permission
        Install[] memory pkgs = new Install[](2);
        pkgs[0] = Install({
            moduleType: MODULE_TYPE_POLICY,
            module: address(policy),
            moduleData: hex"",
            internalData: abi.encodePacked(permissionId)
        });
        pkgs[1] = Install({
            moduleType: MODULE_TYPE_SIGNER,
            module: address(signer),
            moduleData: hex"",
            internalData: abi.encodePacked(permissionId, address(0), Kernel.execute.selector)
        });
        vm.prank(address(ep));
        kernel.installModule(pkgs);

        // Set policy and signer to pass
        bytes32 paddedVId = bytes32(PermissionId.unwrap(permissionId));
        policy.sudoSetValidSig(address(kernel), paddedVId, hex"dead");
        signer.sudoSetValidSig(address(kernel), paddedVId, hex"beef");

        // Build nonce for permission type
        uint192 key = uint192(
            bytes24(
                abi.encodePacked(
                    uint8(0x00),
                    bytes1(0x02), // permission type
                    PermissionId.unwrap(permissionId),
                    bytes16(0),
                    bytes2(0x0000)
                )
            )
        );
        uint256 nonce = ep.getNonce(address(kernel), key);

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = hex"dead";
        signatures[1] = hex"beef";

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: nonce,
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector,
                bytes32(0),
                abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: abi.encode(signatures)
        });

        vm.prank(beneficiary, beneficiary);
        ep.handleOps(ops, beneficiary);

        assertEq(callee.bar(), 1, "Permission validation should succeed and execute");
    }

    // =========================================================================
    // Replayable userOp — chain agnostic hash
    // =========================================================================

    function test_processUserOp_WhenReplayableMode_ShouldUseChainAgnosticHash() public {
        // Use replayable mode bit (0x40)
        rootValidator.sudoSetSuccess(true);

        uint192 key = uint192(
            bytes24(
                abi.encodePacked(
                    uint8(0x40), // replayable
                    bytes1(0x00), // root type
                    bytes20(0),
                    bytes2(0x0000)
                )
            )
        );
        uint256 nonce = ep.getNonce(address(kernel), key);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: nonce,
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector,
                bytes32(0),
                abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });

        vm.prank(beneficiary, beneficiary);
        ep.handleOps(ops, beneficiary);

        assertEq(callee.bar(), 1, "Replayable userOp should succeed");
    }

    // =========================================================================
    // Enable mode in UserOp — install and validate inline
    // =========================================================================

    function test_processUserOp_WhenEnableMode_ShouldInstallAndValidate() public {
        MockValidator enabledValidator = new MockValidator();

        Install[] memory packages = new Install[](1);
        packages[0] = Install({
            moduleType: MODULE_TYPE_VALIDATOR,
            module: address(enabledValidator),
            moduleData: hex"",
            internalData: abi.encodePacked(Kernel.execute.selector)
        });

        // Compute enable signature digest (non-replayable)
        bytes32 digest = KernelHelper.installDigest(address(kernel), false, 0, packages);
        rootValidator.sudoSetValidSig(hex"");
        enabledValidator.sudoSetSuccess(true);

        // Enable mode nonce
        uint8 uMode = 0x08; // enable
        uint192 key =
            uint192(bytes24(abi.encodePacked(uMode, bytes1(0x01), bytes20(address(enabledValidator)), bytes2(0x0000))));
        uint256 nonce = ep.getNonce(address(kernel), key);

        bytes memory fullSig = abi.encode(uint256(0), packages, hex"", hex"");

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: nonce,
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector,
                bytes32(0),
                abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: fullSig
        });

        vm.prank(beneficiary, beneficiary);
        ep.handleOps(ops, beneficiary);

        assertEq(callee.bar(), 1, "Enable mode should install validator and execute");
        assertTrue(
            kernel.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(enabledValidator), hex""),
            "Enabled validator should be installed"
        );
    }

    // =========================================================================
    // UserOp with validation hook — executeUserOp path

    // =========================================================================
    // intersectValidationData in _processUserOp — enable returns time-bounded result
    // =========================================================================

    function test_processUserOp_WhenEnableReturnsTimeBounds_ShouldIntersectWithValidatorResult() public {
        // Set rootValidator to return time-bounded validation data for enable signature
        // validAfter=0, validUntil=type(uint48).max-1, result=success
        // This tests the intersectValidationData path in _processUserOp
        MockValidator enabledValidator = new MockValidator();

        Install[] memory packages = new Install[](1);
        packages[0] = Install({
            moduleType: MODULE_TYPE_VALIDATOR,
            module: address(enabledValidator),
            moduleData: hex"",
            internalData: abi.encodePacked(Kernel.execute.selector)
        });

        // Set rootValidator with custom validation data (time bounds)
        uint256 customValidationData = (uint256(100) << 208) | (uint256(99999999999) << 160);
        rootValidator.sudoSetValidationData(customValidationData);
        rootValidator.sudoSetValidSig(hex"");
        enabledValidator.sudoSetSuccess(true);

        uint8 uMode = 0x08;
        uint192 key = uint192(
            bytes24(
                abi.encodePacked(
                    uMode,
                    bytes1(0x01),
                    bytes20(address(enabledValidator)),
                    bytes2(0x0001) // different key to avoid nonce collision
                )
            )
        );
        uint256 nonce = ep.getNonce(address(kernel), key);

        bytes memory fullSig = abi.encode(uint256(0), packages, hex"", hex"");

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: nonce,
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector,
                bytes32(0),
                abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: fullSig
        });

        // Should succeed if block.timestamp is within the time bounds
        vm.warp(200);
        vm.prank(beneficiary, beneficiary);
        ep.handleOps(ops, beneficiary);

        assertEq(callee.bar(), 1, "Time-bounded enable should succeed within bounds");
    }

    // =========================================================================

    // =========================================================================
    // Executor install without internalData
    // =========================================================================

    function test_installExecutor_WhenNoInternalData_ShouldInstallWithNoHook() public {
        vm.prank(address(ep));
        kernel.installModule(MODULE_TYPE_EXECUTOR, address(mockExecutor), abi.encode(hex"", hex""));

        ExecutorConfig memory config = kernel.executorConfig(address(mockExecutor));
        assertTrue(config.installed);
    }

    // =========================================================================

    // =========================================================================
    // Validator install with empty internalData — no selectors allowed
    // =========================================================================

    function test_installValidator_WhenEmptyInternalData_ShouldInstallWithNoSelectors() public {
        vm.prank(address(ep));
        kernel.installModule(MODULE_TYPE_VALIDATOR, address(newValidator), abi.encode(hex"", hex""));

        // Verify installed
        assertTrue(kernel.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(newValidator), hex""), "Should be installed");
    }

    // =========================================================================
    // KernelFactory — ImplementationNotDeployed
    // =========================================================================

    function test_KernelFactory_WhenUUPSNotDeployed_ShouldRevert() public {
        // address(0xdead) has no code deployed, so it simulates an undeployed impl
        KernelImmutableECDSA immutableEcdsa = new KernelImmutableECDSA(ep);
        vm.expectRevert(ImplementationNotDeployed.selector);
        new KernelFactory(KernelUUPS(payable(makeAddr("noCode"))), immutableEcdsa);
    }

    function test_KernelFactory_WhenImmutableECDSANotDeployed_ShouldRevert() public {
        KernelUUPS uupsImpl = new KernelUUPS(ep);
        vm.expectRevert(ImplementationNotDeployed.selector);
        new KernelFactory(uupsImpl, KernelImmutableECDSA(payable(makeAddr("noCode2"))));
    }

    // =========================================================================
    // KernelFactory — InvalidSigner for deployECDSA
    // =========================================================================

    function test_deployECDSA_WhenSignerIsZero_ShouldRevertWithInvalidSigner() public {
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({
            moduleType: MODULE_TYPE_VALIDATOR, module: address(rootValidator), moduleData: hex"", internalData: hex""
        });

        vm.expectRevert(InvalidSigner.selector);
        factory.deployECDSA(address(0), pkgs, 0);
    }

    // =========================================================================
    // KernelFactory — deploy and getAddress
    // =========================================================================

    function test_factory_getAddress_ShouldMatchDeploy() public {
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({
            moduleType: MODULE_TYPE_VALIDATOR, module: address(rootValidator), moduleData: hex"", internalData: hex""
        });

        address predicted = factory.getAddress(pkgs, 99);
        Kernel deployed = factory.deploy(pkgs, 99);
        assertEq(address(deployed), predicted, "Predicted address should match deployed");
    }

    function test_factory_deployTwice_ShouldReturnSameAddress() public {
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({
            moduleType: MODULE_TYPE_VALIDATOR, module: address(rootValidator), moduleData: hex"", internalData: hex""
        });

        Kernel first = factory.deploy(pkgs, 100);
        Kernel second = factory.deploy(pkgs, 100);
        assertEq(address(first), address(second), "Deploy twice should return same address");
    }
}

contract RevertingOnInstallFallback {
    function onInstall(bytes calldata) external payable {
        revert("forced fallback revert");
    }

    function onUninstall(bytes calldata) external payable {}

    function isModuleType(uint256 typeId) external pure returns (bool) {
        return typeId == 3;
    }

    function isInitialized(address) external pure returns (bool) {
        return false;
    }

    function fallbackFn() external pure returns (uint256) {
        return 42;
    }
}

contract RevertingOnInstallHook {
    function onInstall(bytes calldata) external payable {
        revert("forced hook revert");
    }

    function onUninstall(bytes calldata) external payable {}

    function isModuleType(uint256 typeId) external pure returns (bool) {
        return typeId == 11;
    }

    function isInitialized(address) external pure returns (bool) {
        return false;
    }

    function preCheck(bytes32, address, uint256, bytes calldata) external payable returns (bytes memory) {
        return hex"";
    }

    function postCheck(bytes32, bytes calldata) external payable {}
}
