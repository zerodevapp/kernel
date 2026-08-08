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
import {MockFallback} from "../mock/MockFallback.sol";
import {MockExecutor} from "../mock/MockExecutor.sol";
import {MockCallee} from "../mock/MockCallee.sol";
import {MockHook} from "../mock/MockHook.sol";
import {ChainAgnosticHashHelper} from "../utils/ChainAgnosticHashHelper.sol";
import {
    NotImplemented,
    Unauthorized,
    UnauthorizedCallData,
    InvalidSelector,
    InvalidCallType,
    InvalidExecType,
    InvalidVid,
    InvalidRootValidation,
    InvalidInitialization,
    InvalidDataLength,
    InvalidNonce,
    InvalidValidationType,
    InvalidPermissionUninstallOrder,
    InvalidPermissionId,
    InvalidSignature,
    OccupiedValidationId,
    CannotUninstallRoot,
    NotExecutor,
    ModuleInstallFailed,
    PermissionInstallNotFinished,
    InvalidPermissionInstall,
    InstallSignatureVerificationFailed,
    InvalidSigner,
    ImplementationNotDeployed
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
    SIG_VALIDATION_SUCCESS_UINT,
    VALIDATION_TYPE_ROOT,
    VALIDATION_TYPE_VALIDATOR,
    VALIDATION_TYPE_PERMISSION,
    MODULE_TYPE_SCOPED_EXECUTION_HOOK,
    SCOPED_EXECUTION_HOOK_SELECTOR_SCOPE,
    SELECTOR_MANAGER_STORAGE_SLOT
} from "src/types/Constants.sol";
import {validatorToIdentifier, permissionToIdentifier} from "src/lib/Utils.sol";
import {IValidator, IExecutor} from "src/interfaces/IERC7579Modules.sol";
import {IERC7579Account} from "src/interfaces/IERC7579Account.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";

/// @notice Comprehensive unit tests for Kernel.sol to close coverage gaps.
contract KernelCoverageTest is Test {
    IEntryPoint ep;
    KernelFactory factory;
    KernelUUPS uups;
    Kernel kernel;
    MockValidator rootValidator;
    MockValidator newValidator;
    MockPolicy policy;
    MockSigner signer;
    MockFallback mockFallback;
    MockExecutor mockExecutor;
    MockCallee callee;
    MockHook mockHook;
    address payable beneficiary;
    PermissionId permissionId;
    ChainAgnosticHashHelper hashHelper;

    function setUp() public {
        ep = EntryPointLib.deploy();
        uups = new KernelUUPS(ep);
        KernelImmutableECDSA immutableEcdsa = new KernelImmutableECDSA(ep);
        factory = new KernelFactory(uups, immutableEcdsa);
        rootValidator = new MockValidator();
        newValidator = new MockValidator();
        policy = new MockPolicy();
        signer = new MockSigner();
        mockFallback = new MockFallback();
        mockExecutor = new MockExecutor();
        callee = new MockCallee();
        mockHook = new MockHook();
        beneficiary = payable(makeAddr("Beneficiary"));
        hashHelper = new ChainAgnosticHashHelper();
        permissionId = PermissionId.wrap(bytes4(keccak256(abi.encodePacked("TestPermission"))));

        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({
            moduleType: MODULE_TYPE_VALIDATOR, module: address(rootValidator), moduleData: hex"", internalData: hex""
        });
        kernel = factory.deploy(pkgs, 0);
        vm.deal(address(kernel), 10 ether);
    }

    // =========================================================================
    // View functions: accountId, supportsModule, supportsExecutionMode
    // =========================================================================

    function test_accountId_ShouldReturnCorrectString() public view {
        string memory id = kernel.accountId();
        assertEq(id, "kernel.v0.4", "accountId should return kernel.v0.4");
    }

    function test_supportsModule_WhenTypeIsZero_ShouldReturnFalse() public view {
        assertFalse(kernel.supportsModule(0), "Module type 0 should not be supported");
    }

    function test_supportsModule_WhenTypeIsSupported_ShouldReturnTrue() public view {
        assertTrue(kernel.supportsModule(1));
        assertTrue(kernel.supportsModule(2));
        assertTrue(kernel.supportsModule(3));
        assertFalse(kernel.supportsModule(4));
        assertTrue(kernel.supportsModule(5));
        assertTrue(kernel.supportsModule(6));
        assertTrue(kernel.supportsModule(11));
    }

    function test_supportsModule_WhenTypeIs7_ShouldReturnFalse() public view {
        assertFalse(kernel.supportsModule(7), "Module type 7 should not be supported");
    }

    function test_supportsModule_WhenTypeIs255_ShouldReturnFalse() public view {
        assertFalse(kernel.supportsModule(255), "Module type 255 should not be supported");
    }

    function test_supportsExecutionMode_WhenSingleDefault_ShouldReturnTrue() public view {
        bytes32 mode = bytes32(
            abi.encodePacked(LibERC7579.CALLTYPE_SINGLE, LibERC7579.EXECTYPE_DEFAULT, bytes4(0), bytes4(0), bytes22(0))
        );
        assertTrue(kernel.supportsExecutionMode(mode), "Single+Default should be supported");
    }

    function test_supportsExecutionMode_WhenBatchTry_ShouldReturnTrue() public view {
        bytes32 mode = bytes32(
            abi.encodePacked(LibERC7579.CALLTYPE_BATCH, LibERC7579.EXECTYPE_TRY, bytes4(0), bytes4(0), bytes22(0))
        );
        assertTrue(kernel.supportsExecutionMode(mode), "Batch+Try should be supported");
    }

    function test_supportsExecutionMode_WhenDelegatecallDefault_ShouldReturnTrue() public view {
        bytes32 mode = bytes32(
            abi.encodePacked(
                LibERC7579.CALLTYPE_DELEGATECALL, LibERC7579.EXECTYPE_DEFAULT, bytes4(0), bytes4(0), bytes22(0)
            )
        );
        assertTrue(kernel.supportsExecutionMode(mode), "Delegatecall+Default should be supported");
    }

    function test_supportsExecutionMode_WhenInvalidCallType_ShouldReturnFalse() public view {
        bytes32 mode =
            bytes32(abi.encodePacked(bytes1(0x03), LibERC7579.EXECTYPE_DEFAULT, bytes4(0), bytes4(0), bytes22(0)));
        assertFalse(kernel.supportsExecutionMode(mode), "Invalid callType should not be supported");
    }

    function test_supportsExecutionMode_WhenInvalidExecType_ShouldReturnFalse() public view {
        bytes32 mode =
            bytes32(abi.encodePacked(LibERC7579.CALLTYPE_SINGLE, bytes1(0x02), bytes4(0), bytes4(0), bytes22(0)));
        assertFalse(kernel.supportsExecutionMode(mode), "Invalid execType should not be supported");
    }

    // =========================================================================
    // isModuleInstalled — all 6 types + uninstalled + type 7 revert
    // =========================================================================

    function test_isModuleInstalled_WhenValidatorInstalled_ShouldReturnTrue() public view {
        assertTrue(
            kernel.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(rootValidator), hex""),
            "Root validator should be installed"
        );
    }

    function test_isModuleInstalled_WhenValidatorNotInstalled_ShouldReturnFalse() public view {
        assertFalse(
            kernel.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(newValidator), hex""),
            "New validator should not be installed"
        );
    }

    function test_isModuleInstalled_WhenExecutorInstalled_ShouldReturnTrue() public {
        vm.prank(address(ep));
        kernel.installModule(MODULE_TYPE_EXECUTOR, address(mockExecutor), abi.encode(hex"", hex""));
        assertTrue(
            kernel.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(mockExecutor), hex""), "Executor should be installed"
        );
    }

    function test_isModuleInstalled_WhenExecutorNotInstalled_ShouldReturnFalse() public view {
        assertFalse(
            kernel.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(mockExecutor), hex""),
            "Executor should not be installed"
        );
    }

    function test_isModuleInstalled_WhenFallbackInstalled_ShouldReturnTrue() public {
        bytes4 testSel = MockFallback.testFunction.selector;
        vm.prank(address(ep));
        kernel.installModule(
            MODULE_TYPE_FALLBACK, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSel, bytes1(0x00)))
        );
        assertTrue(
            kernel.isModuleInstalled(MODULE_TYPE_FALLBACK, address(mockFallback), abi.encodePacked(testSel)),
            "Fallback should be installed"
        );
    }

    function test_isModuleInstalled_WhenFallbackNotInstalled_ShouldReturnFalse() public view {
        assertFalse(
            kernel.isModuleInstalled(
                MODULE_TYPE_FALLBACK, address(mockFallback), abi.encodePacked(MockFallback.testFunction.selector)
            ),
            "Fallback should not be installed"
        );
    }

    function test_isModuleInstalled_WhenPolicyInstalled_ShouldReturnTrue() public {
        // Install policy + signer for a permission
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

        assertTrue(
            kernel.isModuleInstalled(MODULE_TYPE_POLICY, address(policy), abi.encodePacked(permissionId)),
            "Policy should be installed"
        );
    }

    function test_isModuleInstalled_WhenPolicyNotInstalled_ShouldReturnFalse() public view {
        assertFalse(
            kernel.isModuleInstalled(MODULE_TYPE_POLICY, address(policy), abi.encodePacked(permissionId)),
            "Policy should not be installed for this permissionId"
        );
    }

    function test_isModuleInstalled_WhenSignerInstalled_ShouldReturnTrue() public {
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

        assertTrue(
            kernel.isModuleInstalled(MODULE_TYPE_SIGNER, address(signer), abi.encodePacked(permissionId)),
            "Signer should be installed"
        );
    }

    function test_isModuleInstalled_WhenSignerNotInstalled_ShouldReturnFalse() public view {
        assertFalse(
            kernel.isModuleInstalled(MODULE_TYPE_SIGNER, address(signer), abi.encodePacked(permissionId)),
            "Signer should not be installed"
        );
    }

    function test_isModuleInstalled_WhenModuleTypeIs7_ShouldRevertWithNotImplemented() public {
        vm.expectRevert(NotImplemented.selector);
        kernel.isModuleInstalled(7, address(0x1234), hex"");
    }

    // =========================================================================
    // Unauthorized — callers other than entrypoint or self
    // =========================================================================

    function test_execute_WhenCallerIsNotEntryPointOrSelf_ShouldRevertWithUnauthorized() public {
        address random = makeAddr("Random");
        vm.prank(random);
        vm.expectRevert(Unauthorized.selector);
        kernel.execute(bytes32(0), hex"");
    }

    function test_installModule_WhenCallerIsNotEntryPointOrSelf_ShouldRevertWithUnauthorized() public {
        address random = makeAddr("Random");
        vm.prank(random);
        vm.expectRevert(Unauthorized.selector);
        kernel.installModule(MODULE_TYPE_VALIDATOR, address(newValidator), abi.encode(hex"", hex""));
    }

    function test_uninstallModule_WhenCallerIsNotEntryPointOrSelf_ShouldRevertWithUnauthorized() public {
        address random = makeAddr("Random");
        vm.prank(random);
        vm.expectRevert(Unauthorized.selector);
        kernel.uninstallModule(MODULE_TYPE_VALIDATOR, address(newValidator), abi.encode(hex"", hex""));
    }

    function test_setNonce_WhenCallerIsNotEntryPointOrSelf_ShouldRevertWithUnauthorized() public {
        address random = makeAddr("Random");
        vm.prank(random);
        vm.expectRevert(Unauthorized.selector);
        kernel.setNonce(0, 1);
    }

    function test_setValidNonceFrom_WhenCallerIsNotEntryPointOrSelf_ShouldRevertWithUnauthorized() public {
        address random = makeAddr("Random");
        vm.prank(random);
        vm.expectRevert(Unauthorized.selector);
        kernel.setValidNonceFrom(1);
    }

    function test_validateUserOp_WhenCallerIsNotEntryPointOrSelf_ShouldRevertWithUnauthorized() public {
        address random = makeAddr("Random");
        PackedUserOperation memory op;
        op.sender = address(kernel);
        vm.prank(random);
        vm.expectRevert(Unauthorized.selector);
        kernel.validateUserOp(op, bytes32(0), 0);
    }

    function test_executeUserOp_WhenCallerIsNotEntryPointOrSelf_ShouldRevertWithUnauthorized() public {
        address random = makeAddr("Random");
        PackedUserOperation memory op;
        op.sender = address(kernel);
        op.callData = abi.encodePacked(Kernel.executeUserOp.selector, hex"deadbeef");
        vm.prank(random);
        vm.expectRevert(Unauthorized.selector);
        kernel.executeUserOp(op, bytes32(0));
    }

    // =========================================================================
    // InvalidInitialization — setRoot with empty packages
    // =========================================================================

    function test_setRoot_WhenPackagesEmpty_ShouldRevertWithInvalidInitialization() public {
        Install[] memory pkgs = new Install[](0);
        vm.prank(address(ep));
        vm.expectRevert(InvalidInitialization.selector);
        kernel.setRoot(pkgs, false, hex"");
    }

    // =========================================================================
    // InvalidRootValidation — setRoot with executor module
    // =========================================================================

    function test_setRoot_WhenModuleTypeIsExecutor_ShouldRevertWithInvalidRootValidation() public {
        vm.startPrank(address(ep));
        kernel.installModule(MODULE_TYPE_EXECUTOR, address(mockExecutor), abi.encode(hex"", hex""));

        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({
            moduleType: MODULE_TYPE_EXECUTOR, module: address(mockExecutor), moduleData: hex"", internalData: hex""
        });
        vm.expectRevert(InvalidRootValidation.selector);
        kernel.setRoot(pkgs, false, hex"");
        vm.stopPrank();
    }

    // =========================================================================
    // setRoot with removeCurrent=true (validator and permission paths)
    // =========================================================================

    function test_setRoot_WhenRemoveCurrentValidator_ShouldUninstallOldRoot() public {
        vm.startPrank(address(ep));

        // setRoot(pkgs, removeCurrent, ...) calls _install(pkgs) then _setRoot then uninstalls old.
        // So pkgs[0] must be a NEW module not yet installed, or already installed but different from old root.
        // Use a brand-new validator to avoid OccupiedValidationId.
        MockValidator freshValidator = new MockValidator();
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({
            moduleType: MODULE_TYPE_VALIDATOR, module: address(freshValidator), moduleData: hex"", internalData: hex""
        });
        kernel.setRoot(pkgs, true, hex"");

        // Verify old root is uninstalled
        ValidationId oldVid = validatorToIdentifier(IValidator(address(rootValidator)));
        ValidationInfo memory info = kernel.validationInfo(oldVid);
        assertFalse(info.installed, "Old root validator should be uninstalled");

        // Verify new root is set
        ValidationId newRoot = kernel.root();
        assertTrue(
            newRoot == validatorToIdentifier(IValidator(address(freshValidator))), "New root should be freshValidator"
        );
        vm.stopPrank();
    }

    function test_setRoot_WhenRemoveCurrentPermission_ShouldUninstallOldPermission() public {
        vm.startPrank(address(ep));

        // Install permission, then set as root
        Install[] memory permPkgs = new Install[](2);
        permPkgs[0] = Install({
            moduleType: MODULE_TYPE_POLICY,
            module: address(policy),
            moduleData: hex"",
            internalData: abi.encodePacked(permissionId)
        });
        permPkgs[1] = Install({
            moduleType: MODULE_TYPE_SIGNER,
            module: address(signer),
            moduleData: hex"",
            internalData: abi.encodePacked(permissionId, address(0), Kernel.execute.selector)
        });
        kernel.installModule(permPkgs);

        ValidationId permVid = permissionToIdentifier(permissionId);
        kernel.setRoot(permVid);

        // setRoot(pkgs, removeCurrent=true) calls _install(pkgs) first, so pkgs must
        // contain a NEW validator to avoid OccupiedValidationId
        MockValidator freshValidator = new MockValidator();
        Install[] memory newPkgs = new Install[](1);
        newPkgs[0] = Install({
            moduleType: MODULE_TYPE_VALIDATOR, module: address(freshValidator), moduleData: hex"", internalData: hex""
        });

        bytes[] memory uninstallDataArr = new bytes[](2);
        uninstallDataArr[0] = hex""; // policy
        uninstallDataArr[1] = hex""; // signer

        kernel.setRoot(newPkgs, true, abi.encode(uninstallDataArr));

        ValidationInfo memory info = kernel.validationInfo(permVid);
        assertFalse(info.installed, "Old permission root should be uninstalled");
        vm.stopPrank();
    }

    // =========================================================================
    // InvalidDataLength — setRoot removeCurrent permission with wrong uninstallData length
    // =========================================================================

    function test_setRoot_WhenRemovePermissionWithWrongDataLength_ShouldRevertWithInvalidDataLength() public {
        vm.startPrank(address(ep));

        Install[] memory permPkgs = new Install[](2);
        permPkgs[0] = Install({
            moduleType: MODULE_TYPE_POLICY,
            module: address(policy),
            moduleData: hex"",
            internalData: abi.encodePacked(permissionId)
        });
        permPkgs[1] = Install({
            moduleType: MODULE_TYPE_SIGNER,
            module: address(signer),
            moduleData: hex"",
            internalData: abi.encodePacked(permissionId, address(0), Kernel.execute.selector)
        });
        kernel.installModule(permPkgs);

        ValidationId permVid = permissionToIdentifier(permissionId);
        kernel.setRoot(permVid);

        // Use a fresh validator to avoid OccupiedValidationId
        MockValidator freshValidator = new MockValidator();
        Install[] memory newPkgs = new Install[](1);
        newPkgs[0] = Install({
            moduleType: MODULE_TYPE_VALIDATOR, module: address(freshValidator), moduleData: hex"", internalData: hex""
        });

        // Wrong length: only 1 instead of 2 (1 policy + 1 signer)
        bytes[] memory wrongLen = new bytes[](1);
        wrongLen[0] = hex"";

        vm.expectRevert(InvalidDataLength.selector);
        kernel.setRoot(newPkgs, true, abi.encode(wrongLen));
        vm.stopPrank();
    }

    // =========================================================================
    // InvalidVid — using uninstalled validation
    // =========================================================================

    function test_validateUserOp_WhenVidNotInstalled_ShouldRevertWithInvalidVid() public {
        // Try to use a validator type nonce with an uninstalled validator
        uint192 key = uint192(
            bytes24(
                abi.encodePacked(
                    uint8(0x00), // mode: standard
                    bytes1(0x01), // type: validator
                    bytes20(address(newValidator)),
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

        // This will fail inside the entrypoint because validateUserOp reverts with InvalidVid
        vm.expectRevert();
        vm.prank(beneficiary, beneficiary);
        ep.handleOps(ops, beneficiary);
    }

    // =========================================================================
    // SIG_VALIDATION_FAILED — validator returns failure
    // =========================================================================

    function test_processUserOp_WhenValidatorReturnsFailed_ShouldReturnSigValidationFailed() public {
        // Root validator returns failure
        rootValidator.sudoSetSuccess(false);

        uint192 key = uint192(
            bytes24(
                abi.encodePacked(
                    uint8(0x00),
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

        // EntryPoint will revert because validation failed
        vm.expectRevert();
        vm.prank(beneficiary, beneficiary);
        ep.handleOps(ops, beneficiary);
    }

    // =========================================================================
    // UnauthorizedCallData — non-root validation with wrong selector
    // =========================================================================

    function test_processUserOp_WhenNonRootValidationWithDisallowedSelector_ShouldRevert() public {
        // Install a validator with specific selectors allowed
        vm.prank(address(ep));
        kernel.installModule(
            MODULE_TYPE_VALIDATOR, address(newValidator), abi.encode(hex"", abi.encodePacked(Kernel.execute.selector))
        );

        newValidator.sudoSetSuccess(true);

        // Use the validator but call executeUserOp with a callData that targets a disallowed selector
        // The nonce uses the new validator (non-root), and the callData has an inner selector
        // that is NOT in the allowed list
        uint192 key = uint192(
            bytes24(
                abi.encodePacked(
                    uint8(0x00),
                    bytes1(0x01), // validator type
                    bytes20(address(newValidator)),
                    bytes2(0x0000)
                )
            )
        );
        uint256 nonce = ep.getNonce(address(kernel), key);

        // Build a callData that targets an unauthorized function via executeUserOp
        // Use IERC7579Account.installModule.selector to avoid ambiguity with Kernel overloads
        bytes memory innerCall = abi.encodeWithSelector(
            bytes4(keccak256("installModule(uint256,address,bytes)")), MODULE_TYPE_VALIDATOR, address(0x1234), hex""
        );
        bytes memory callData = abi.encodeWithSelector(Kernel.executeUserOp.selector, innerCall);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: nonce,
            initCode: hex"",
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });

        // Should revert because Kernel.installModule.selector is not allowed for this validation
        vm.expectRevert();
        vm.prank(beneficiary, beneficiary);
        ep.handleOps(ops, beneficiary);
    }

    // =========================================================================
    // Nonce management — setNonce and setValidNonceFrom
    // =========================================================================

    function test_setNonce_WhenValid_ShouldSucceed() public {
        vm.prank(address(ep));
        kernel.setNonce(0, 1);
        // Verify no revert
    }

    function test_setNonce_WhenNotIncreasing_ShouldRevertWithInvalidNonce() public {
        vm.startPrank(address(ep));
        kernel.setNonce(0, 5);
        vm.expectRevert(InvalidNonce.selector);
        kernel.setNonce(0, 3); // lower than current
        vm.stopPrank();
    }

    function test_setValidNonceFrom_WhenValid_ShouldSucceed() public {
        vm.prank(address(ep));
        kernel.setValidNonceFrom(1);
        assertEq(kernel.validNonceFrom(), 1, "validNonceFrom should be 1");
    }

    function test_setValidNonceFrom_WhenNotIncreasing_ShouldRevertWithInvalidNonce() public {
        vm.startPrank(address(ep));
        kernel.setValidNonceFrom(5);
        vm.expectRevert(InvalidNonce.selector);
        kernel.setValidNonceFrom(3);
        vm.stopPrank();
    }

    // =========================================================================
    // InvalidSelector — calling uninstalled fallback
    // =========================================================================

    function test_fallback_WhenSelectorNotInstalled_ShouldRevertWithInvalidSelector() public {
        vm.expectRevert(InvalidSelector.selector);
        MockFallback(address(kernel)).testFunction();
    }

    function test_fallback_WhenInstalled_ShouldSucceed() public {
        bytes4 testSel = MockFallback.testFunction.selector;
        vm.prank(address(ep));
        kernel.installModule(
            MODULE_TYPE_FALLBACK, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSel, bytes1(0x00)))
        );

        // Entrypoint caller should succeed
        vm.prank(address(ep));
        uint256 result = MockFallback(address(kernel)).testFunction();
        assertEq(result, 42, "Fallback should return 42");
    }

    // =========================================================================
    // Fallback with CALLTYPE_DELEGATECALL
    // =========================================================================

    function test_fallback_WhenCallTypeDelegatecall_ShouldDelegatecall() public {
        bytes4 testSel = MockFallback.testFunction.selector;
        vm.startPrank(address(ep));
        kernel.installModule(
            MODULE_TYPE_FALLBACK, address(mockFallback), abi.encode(hex"", abi.encodePacked(testSel, bytes1(0xFF)))
        );
        // Selectors without a scoped execution hook are EntryPoint-only; install a
        // passthrough scoped hook so the delegatecall fallback is publicly callable.
        kernel.installModule(
            MODULE_TYPE_SCOPED_EXECUTION_HOOK,
            address(mockHook),
            abi.encode(hex"", abi.encodePacked(SCOPED_EXECUTION_HOOK_SELECTOR_SCOPE, testSel))
        );
        vm.stopPrank();

        // Anyone can call an installed fallback that has a scoped execution hook
        // (testFunction() is view, so use a raw non-static call to allow the hook's pre/post checks)
        (bool success, bytes memory ret) = address(kernel).call(abi.encodePacked(testSel));
        assertTrue(success, "Delegatecall fallback should succeed");
        uint256 result = abi.decode(ret, (uint256));
        assertEq(result, 42, "Delegatecall fallback should return 42");
    }

    // =========================================================================
    // installModule + uninstallModule with NotImplemented for type 7
    // =========================================================================

    function test_installModule_WhenModuleTypeIs7_ShouldRevertWithNotImplemented() public {
        vm.prank(address(ep));
        vm.expectRevert(NotImplemented.selector);
        kernel.installModule(7, address(0x1234), abi.encode(hex"", hex""));
    }

    function test_uninstallModule_WhenModuleTypeIs7_ShouldRevertWithNotImplemented() public {
        vm.prank(address(ep));
        vm.expectRevert(NotImplemented.selector);
        kernel.uninstallModule(7, address(0x1234), abi.encode(hex"", hex""));
    }

    // =========================================================================
    // grantAccess — InvalidDataLength when selectors not multiple of 4
    // =========================================================================

    function test_grantAccess_WhenSelectorsNotMultipleOf4_ShouldRevertWithInvalidDataLength() public {
        ValidationId vId = validatorToIdentifier(IValidator(address(rootValidator)));
        vm.prank(address(ep));
        vm.expectRevert(InvalidDataLength.selector);
        kernel.grantAccess(vId, hex"112233"); // 3 bytes, not multiple of 4
    }

    function test_grantAccess_WhenValid_ShouldSucceed() public {
        ValidationId vId = validatorToIdentifier(IValidator(address(rootValidator)));
        vm.prank(address(ep));
        kernel.grantAccess(vId, abi.encodePacked(Kernel.execute.selector));
    }

    // =========================================================================
    // installModule(replayable, nonce, packages, signature) — signature verification failed
    // =========================================================================

    function test_installModuleWithSignature_WhenSignatureInvalid_ShouldRevertWithInstallSignatureVerificationFailed()
        public
    {
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({
            moduleType: MODULE_TYPE_VALIDATOR, module: address(newValidator), moduleData: hex"", internalData: hex""
        });

        // Don't set valid sig on rootValidator => signature verification fails
        vm.expectRevert(InstallSignatureVerificationFailed.selector);
        kernel.installModule(false, 0, pkgs, hex"deadbeef");
    }

    // =========================================================================
    // InvalidPermissionUninstallOrder — uninstall policy out of order
    // =========================================================================

    function test_uninstallPolicy_WhenNotLast_ShouldRevertWithInvalidPermissionUninstallOrder() public {
        // Install two policies + signer
        MockPolicy policy2 = new MockPolicy();
        Install[] memory pkgs = new Install[](3);
        pkgs[0] = Install({
            moduleType: MODULE_TYPE_POLICY,
            module: address(policy),
            moduleData: hex"",
            internalData: abi.encodePacked(permissionId)
        });
        pkgs[1] = Install({
            moduleType: MODULE_TYPE_POLICY,
            module: address(policy2),
            moduleData: hex"",
            internalData: abi.encodePacked(permissionId)
        });
        pkgs[2] = Install({
            moduleType: MODULE_TYPE_SIGNER,
            module: address(signer),
            moduleData: hex"",
            internalData: abi.encodePacked(permissionId, address(0), Kernel.execute.selector)
        });
        vm.startPrank(address(ep));
        kernel.installModule(pkgs);

        // Try to uninstall the first policy (not last in array) => out of order
        vm.expectRevert(InvalidPermissionUninstallOrder.selector);
        kernel.uninstallModule(MODULE_TYPE_POLICY, address(policy), abi.encode(hex"", abi.encodePacked(permissionId)));
        vm.stopPrank();
    }

    // =========================================================================
    // InvalidPermissionId — uninstall signer with wrong address
    // =========================================================================

    function test_uninstallSigner_WhenWrongSigner_ShouldRevertWithInvalidPermissionId() public {
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
        vm.startPrank(address(ep));
        kernel.installModule(pkgs);

        // Uninstall policy first (LIFO)
        kernel.uninstallModule(MODULE_TYPE_POLICY, address(policy), abi.encode(hex"", abi.encodePacked(permissionId)));

        // Try to uninstall wrong signer
        MockSigner wrongSigner = new MockSigner();
        vm.expectRevert(InvalidPermissionId.selector);
        kernel.uninstallModule(
            MODULE_TYPE_SIGNER, address(wrongSigner), abi.encode(hex"", abi.encodePacked(permissionId))
        );
        vm.stopPrank();
    }

    // =========================================================================
    // InvalidPermissionUninstallOrder — uninstall signer with policies still present
    // =========================================================================

    function test_uninstallSigner_WhenPoliciesStillExist_ShouldRevertWithInvalidPermissionUninstallOrder() public {
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
        vm.startPrank(address(ep));
        kernel.installModule(pkgs);

        // Try to uninstall signer without removing policies first
        vm.expectRevert(InvalidPermissionUninstallOrder.selector);
        kernel.uninstallModule(MODULE_TYPE_SIGNER, address(signer), abi.encode(hex"", abi.encodePacked(permissionId)));
        vm.stopPrank();
    }

    // =========================================================================
    // ModuleInstallFailed — validator install when onInstall reverts
    // =========================================================================

    function test_installModule_WhenValidatorOnInstallReverts_ShouldRevertWithModuleInstallFailed() public {
        // Use a mock that reverts on onInstall
        address revertingValidator = address(new RevertingOnInstall());
        vm.prank(address(ep));
        vm.expectRevert(ModuleInstallFailed.selector);
        kernel.installModule(MODULE_TYPE_VALIDATOR, revertingValidator, abi.encode(hex"", hex""));
    }

    // =========================================================================
    // NotExecutor / Unauthorized — executeFromExecutor from non-executor
    // =========================================================================

    function test_executeFromExecutor_WhenCallerNotExecutor_ShouldRevertWithUnauthorized() public {
        address random = makeAddr("Random");
        vm.prank(random);
        vm.expectRevert(Unauthorized.selector);
        kernel.executeFromExecutor(bytes32(0), hex"");
    }

    // =========================================================================
    // InvalidExecType — execution with unsupported exec type
    // =========================================================================

    function test_execute_WhenInvalidExecType_ShouldRevertWithInvalidExecType() public {
        bytes32 mode =
            bytes32(abi.encodePacked(LibERC7579.CALLTYPE_SINGLE, bytes1(0x02), bytes4(0), bytes4(0), bytes22(0)));
        vm.prank(address(ep));
        vm.expectRevert(InvalidExecType.selector);
        kernel.execute(mode, hex"");
    }

    // =========================================================================
    // InvalidCallType — execution with unsupported call type
    // =========================================================================

    function test_execute_WhenInvalidCallType_ShouldRevertWithInvalidCallType() public {
        bytes32 mode =
            bytes32(abi.encodePacked(bytes1(0x03), LibERC7579.EXECTYPE_DEFAULT, bytes4(0), bytes4(0), bytes22(0)));
        vm.prank(address(ep));
        vm.expectRevert(InvalidCallType.selector);
        kernel.execute(mode, hex"");
    }

    // =========================================================================
    // nonce() view — respects validNonceFrom
    // =========================================================================

    function test_nonce_WhenValidNonceFromIsHigher_ShouldReturnValidNonceFrom() public {
        vm.prank(address(ep));
        kernel.setValidNonceFrom(10);

        // nonce for key 0 should now be >= 10
        uint256 n = kernel.nonce(0);
        assertEq(n, 10, "nonce should equal validNonceFrom when current is lower");
    }

    // =========================================================================
    // registry() view
    // =========================================================================

    function test_registry_ShouldReturnZeroByDefault() public view {
        assertEq(kernel.registry(), address(0), "Registry should be address(0) by default");
    }

    // =========================================================================
    // setRoot(ValidationId) — direct set
    // =========================================================================

    function test_setRootById_WhenVidInstalled_ShouldSucceed() public {
        vm.startPrank(address(ep));
        kernel.installModule(MODULE_TYPE_VALIDATOR, address(newValidator), abi.encode(hex"", hex""));
        ValidationId vId = validatorToIdentifier(IValidator(address(newValidator)));
        kernel.setRoot(vId);
        assertTrue(kernel.root() == vId, "Root should be newValidator");
        vm.stopPrank();
    }

    function test_setRootById_WhenVidNotInstalled_ShouldRevertWithInvalidVid() public {
        ValidationId vId = validatorToIdentifier(IValidator(address(newValidator)));
        vm.prank(address(ep));
        vm.expectRevert(abi.encodeWithSelector(InvalidVid.selector, vId));
        kernel.setRoot(vId);
    }

    function test_setRootById_WhenVidIsZero_ShouldRevertWithInvalidRootValidation() public {
        vm.prank(address(ep));
        vm.expectRevert(InvalidRootValidation.selector);
        kernel.setRoot(ValidationId.wrap(bytes21(0)));
    }

    // =========================================================================
    // installModule(Install[] packages) — batch install from entrypoint
    // =========================================================================

    function test_installModuleBatch_WhenCallerIsEntryPoint_ShouldSucceed() public {
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({
            moduleType: MODULE_TYPE_VALIDATOR, module: address(newValidator), moduleData: hex"", internalData: hex""
        });
        vm.prank(address(ep));
        kernel.installModule(pkgs);
        assertTrue(
            kernel.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(newValidator), hex""), "Batch install should work"
        );
    }

    function test_installModuleBatch_WhenCallerIsNotEntryPoint_ShouldRevertWithUnauthorized() public {
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({
            moduleType: MODULE_TYPE_VALIDATOR, module: address(newValidator), moduleData: hex"", internalData: hex""
        });
        address random = makeAddr("Random");
        vm.prank(random);
        vm.expectRevert(Unauthorized.selector);
        kernel.installModule(pkgs);
    }

    // =========================================================================
    // ERC-1271 isValidSignature — root validation path
    // =========================================================================

    function test_isValidSignature_WhenRootValidatorApproves_ShouldReturnMagicValue() public {
        bytes32 testHash = keccak256("test");
        rootValidator.sudoSetValidSig(hex"aabb");

        bytes memory signature = abi.encodePacked(
            bytes1(0x00), // type: root
            hex"aabb" // validator signature
        );

        bytes4 result = kernel.isValidSignature(testHash, signature);
        assertEq(result, ERC1271_MAGICVALUE, "Root validator should approve signature");
    }

    function test_isValidSignature_WhenRootValidatorRejects_ShouldReturnInvalid() public {
        bytes32 testHash = keccak256("test");
        // Don't set valid sig => validator will reject

        bytes memory signature = abi.encodePacked(
            bytes1(0x00), // type: root
            hex"ccdd"
        );

        bytes4 result = kernel.isValidSignature(testHash, signature);
        assertEq(result, ERC1271_INVALID, "Root validator should reject signature");
    }

    // =========================================================================
    // Receive ETH event
    // =========================================================================

    function test_receive_ShouldEmitReceivedEvent() public {
        address sender = makeAddr("EthSender");
        vm.deal(sender, 1 ether);
        vm.prank(sender);
        (bool success,) = address(kernel).call{value: 1 wei}(hex"");
        assertTrue(success, "ETH transfer should succeed");
    }
}

/// @notice Helper contract that always reverts on onInstall
contract RevertingOnInstall {
    function onInstall(bytes calldata) external payable {
        revert("forced revert");
    }

    function onUninstall(bytes calldata) external payable {}

    function isModuleType(uint256 typeId) external pure returns (bool) {
        return typeId == 1;
    }

    function isInitialized(address) external pure returns (bool) {
        return false;
    }
}
