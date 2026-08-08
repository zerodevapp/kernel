pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Kernel} from "src/Kernel.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {KernelImmutableECDSA} from "src/KernelImmutableECDSA.sol";
import {KernelFactory} from "src/KernelFactory.sol";
import {Install, SelectorConfig, ValidationInfo} from "src/types/Structs.sol";
import {ValidationId, CallType, PermissionId} from "src/types/Types.sol";
import {validatorToIdentifier, permissionToIdentifier, getType, getValidator, getPermissionId} from "src/lib/Utils.sol";
import {
    CALLTYPE_DELEGATECALL,
    CALLTYPE_SINGLE,
    VALIDATION_TYPE_VALIDATOR,
    VALIDATION_TYPE_PERMISSION,
    VALIDATION_TYPE_ROOT,
    ERC1271_MAGICVALUE,
    ERC1271_INVALID,
    SIG_VALIDATION_FAILED_UINT,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_POLICY,
    MODULE_TYPE_SIGNER,
    SCOPED_EXECUTION_HOOK_SELECTOR_SCOPE
} from "src/types/Constants.sol";
import {
    Unauthorized,
    InvalidSelector,
    InvalidCallType,
    InvalidVid,
    OccupiedValidationId,
    CannotUninstallRoot,
    InvalidValidationType,
    NotImplemented,
    InvalidDataLength,
    InvalidNonce
} from "src/types/Error.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {MockValidator} from "../mock/MockValidator.sol";
import {MockExecutor} from "../mock/MockExecutor.sol";
import {MockFallback} from "../mock/MockFallback.sol";
import {MockHook} from "../mock/MockHook.sol";
import {MockPolicy} from "../mock/MockPolicy.sol";
import {MockSigner} from "../mock/MockSigner.sol";
import {IERC7579Account} from "src/interfaces/IERC7579Account.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";

contract KernelFuzz is Test {
    Kernel private kernel;
    IEntryPoint private ep;
    MockValidator private rootValidator;
    MockValidator private secondValidator;
    MockExecutor private executor;
    MockFallback private fallbackModule;
    MockPolicy private policy;
    MockSigner private signer;

    function setUp() external {
        ep = EntryPointLib.deploy();
        KernelUUPS uups = new KernelUUPS(ep);
        KernelImmutableECDSA immutableEcdsa = new KernelImmutableECDSA(ep);
        KernelFactory factory = new KernelFactory(uups, immutableEcdsa);
        rootValidator = new MockValidator();
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});
        kernel = factory.deploy(pkgs, 0);

        secondValidator = new MockValidator();
        executor = new MockExecutor();
        fallbackModule = new MockFallback();
        policy = new MockPolicy();
        signer = new MockSigner();

        // Install executor and second validator
        vm.startPrank(address(ep));
        kernel.installModule(2, address(executor), abi.encode(hex"deadbeef", hex""));
        kernel.installModule(1, address(secondValidator), abi.encode(hex"", hex""));
        vm.stopPrank();
    }

    // ========= installModule fuzz tests =========

    /// @dev Installing a validator with random moduleData should never corrupt root
    function testFuzz_installValidator_preservesRoot(bytes calldata moduleData) public {
        ValidationId rootBefore = kernel.root();
        MockValidator v = new MockValidator();
        vm.startPrank(address(ep));
        kernel.installModule(1, address(v), abi.encode(moduleData, hex""));
        vm.stopPrank();
        assertEq(ValidationId.unwrap(kernel.root()), ValidationId.unwrap(rootBefore), "root corrupted after install");
    }

    /// @dev Installing an executor with random moduleData should never corrupt existing executors
    function testFuzz_installExecutor_preservesExistingExecutor(bytes calldata moduleData) public {
        assertTrue(kernel.isModuleInstalled(2, address(executor), hex""), "executor should be installed before");
        MockExecutor newExec = new MockExecutor();
        vm.startPrank(address(ep));
        kernel.installModule(2, address(newExec), abi.encode(moduleData, hex""));
        vm.stopPrank();
        assertTrue(kernel.isModuleInstalled(2, address(executor), hex""), "existing executor corrupted");
        assertTrue(kernel.isModuleInstalled(2, address(newExec), hex""), "new executor not installed");
    }

    /// @dev Installing an invalid module type reverts
    function testFuzz_installModule_invalidType_reverts(uint256 moduleType) public {
        moduleType = bound(moduleType, 7, type(uint256).max);
        vm.assume(moduleType != 11);
        MockValidator v = new MockValidator();
        vm.startPrank(address(ep));
        vm.expectRevert(NotImplemented.selector);
        kernel.installModule(moduleType, address(v), abi.encode(hex"", hex""));
        vm.stopPrank();
    }

    // ========= Validator install/uninstall symmetry =========

    /// @dev install then uninstall returns to uninstalled state
    function testFuzz_validator_installUninstall_symmetry(uint256 seed) public {
        MockValidator v = new MockValidator();
        assertFalse(kernel.isModuleInstalled(1, address(v), hex""), "should start uninstalled");

        vm.startPrank(address(ep));
        kernel.installModule(1, address(v), abi.encode(hex"deadbeef", hex""));
        assertTrue(kernel.isModuleInstalled(1, address(v), hex""), "should be installed");

        kernel.uninstallModule(1, address(v), abi.encode(hex"", hex""));
        vm.stopPrank();
        assertFalse(kernel.isModuleInstalled(1, address(v), hex""), "should be uninstalled again");
    }

    /// @dev Executor install then uninstall returns to uninstalled state
    function testFuzz_executor_installUninstall_symmetry(uint256 seed) public {
        MockExecutor e = new MockExecutor();
        assertFalse(kernel.isModuleInstalled(2, address(e), hex""), "should start uninstalled");

        vm.startPrank(address(ep));
        kernel.installModule(2, address(e), abi.encode(hex"deadbeef", hex""));
        assertTrue(kernel.isModuleInstalled(2, address(e), hex""), "should be installed");

        kernel.uninstallModule(2, address(e), abi.encode(hex"", hex""));
        vm.stopPrank();
        assertFalse(kernel.isModuleInstalled(2, address(e), hex""), "should be uninstalled again");
    }

    // ========= _fallback routing fuzz tests =========

    /// @dev Calling an uninstalled selector always reverts with InvalidSelector
    function testFuzz_fallback_uninstalledSelector_reverts(bytes4 selector) public {
        // Skip ERC721/1155 receiver selectors which are handled by assembly
        if (selector == bytes4(0x150b7a02) || selector == bytes4(0xf23a6e61) || selector == bytes4(0xbc197c81)) return;
        // Skip already installed selectors
        SelectorConfig memory cfg = kernel.selectorConfig(selector);
        if (cfg.target != address(0)) return;

        bytes memory data = abi.encodePacked(selector, bytes20(address(0xBEEF)));
        vm.expectRevert(InvalidSelector.selector);
        (bool success,) = address(kernel).call(data);
        (success);
    }

    /// @dev Installed fallback selectors without a scoped execution hook are EntryPoint-only.
    function testFuzz_fallback_installedSelector_withoutHook_nonEpReverts(address caller) public {
        vm.assume(caller != address(ep));

        bytes4 selector = MockFallback.testFunction.selector;
        bytes1 callType = CallType.unwrap(CALLTYPE_SINGLE);
        bytes memory internalData = abi.encodePacked(selector, callType);
        vm.prank(address(ep));
        kernel.installModule(3, address(fallbackModule), abi.encode(hex"deadbeef", internalData));

        vm.prank(caller);
        (bool success,) = address(kernel).call(abi.encodePacked(selector));
        assertFalse(success, "unhooked selector must not be callable by non-EP callers");
    }

    /// @dev Installed fallback selectors with a scoped execution hook are callable by anyone.
    function testFuzz_fallback_installedSelector_withHook_anyoneCalls(address caller) public {
        vm.assume(caller != address(0));

        MockHook h = new MockHook();
        bytes4 selector = MockFallback.testFunction.selector;
        bytes1 callType = CallType.unwrap(CALLTYPE_SINGLE);
        bytes memory internalData = abi.encodePacked(selector, callType);
        vm.startPrank(address(ep));
        kernel.installModule(3, address(fallbackModule), abi.encode(hex"deadbeef", internalData));
        kernel.installModule(
            11, address(h), abi.encode(hex"deadbeef", abi.encodePacked(SCOPED_EXECUTION_HOOK_SELECTOR_SCOPE, selector))
        );
        vm.stopPrank();

        vm.prank(caller);
        (bool success,) = address(kernel).call(abi.encodePacked(selector));
        assertTrue(success, "hooked selector should be callable by anyone");
    }

    // ========= isValidSignature fuzz tests =========

    /// @dev isValidSignature with root type and invalid sig returns ERC1271_INVALID
    function testFuzz_isValidSignature_invalidSig_returnsInvalid(bytes32 hash, bytes calldata sig) public view {
        bytes memory fullSig = abi.encodePacked(bytes1(0), sig);
        bytes4 ret = kernel.isValidSignature(hash, fullSig);
        assertEq(ret, ERC1271_INVALID, "should return invalid for arbitrary sig");
    }

    /// @dev isValidSignature with invalid validation type (0x03) reverts
    function testFuzz_isValidSignature_invalidType_reverts(bytes32 hash, bytes calldata sig) public {
        bytes memory fullSig = abi.encodePacked(bytes1(0x03), sig);
        vm.expectRevert(InvalidValidationType.selector);
        kernel.isValidSignature(hash, fullSig);
    }

    /// @dev isValidSignature for uninstalled validator reverts with InvalidVid
    function testFuzz_isValidSignature_uninstalledValidator_reverts(bytes32 hash) public {
        MockValidator uninstalled = new MockValidator();
        bytes memory sig =
            hex"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefde";
        bytes memory fullSig = abi.encodePacked(bytes1(0x01), bytes20(address(uninstalled)), sig);
        vm.expectRevert(abi.encodeWithSelector(InvalidVid.selector, validatorToIdentifier(uninstalled)));
        kernel.isValidSignature(hash, fullSig);
    }

    // ========= Access control fuzz tests =========

    /// @dev Only EP or self can call execute
    function testFuzz_execute_unauthorizedCaller_reverts(address caller) public {
        vm.assume(caller != address(ep));
        vm.assume(caller != address(kernel));

        vm.startPrank(caller);
        vm.expectRevert(Unauthorized.selector);
        kernel.execute(bytes32(0), abi.encodePacked(address(kernel), uint256(0), kernel.accountId.selector));
        vm.stopPrank();
    }

    /// @dev Only EP or self can call installModule (single module variant)
    function testFuzz_installModule_unauthorizedCaller_reverts(address caller) public {
        vm.assume(caller != address(ep));
        vm.assume(caller != address(kernel));

        MockValidator v = new MockValidator();
        vm.startPrank(caller);
        vm.expectRevert(Unauthorized.selector);
        kernel.installModule(1, address(v), abi.encode(hex"", hex""));
        vm.stopPrank();
    }

    /// @dev Only EP or self can call uninstallModule
    function testFuzz_uninstallModule_unauthorizedCaller_reverts(address caller) public {
        vm.assume(caller != address(ep));
        vm.assume(caller != address(kernel));

        vm.startPrank(caller);
        vm.expectRevert(Unauthorized.selector);
        kernel.uninstallModule(1, address(secondValidator), abi.encode(hex"", hex""));
        vm.stopPrank();
    }

    // ========= setRoot fuzz tests =========

    /// @dev setRoot to an installed validator updates root correctly
    function testFuzz_setRoot_installedValidator_succeeds(uint256 index) public {
        // Install a new validator
        MockValidator v = new MockValidator();
        vm.startPrank(address(ep));
        kernel.installModule(1, address(v), abi.encode(hex"deadbeef", hex""));

        ValidationId vId = validatorToIdentifier(v);
        kernel.setRoot(vId);
        vm.stopPrank();

        assertEq(ValidationId.unwrap(kernel.root()), ValidationId.unwrap(vId), "root not updated");
    }

    /// @dev setRoot to an uninstalled validator reverts
    function testFuzz_setRoot_uninstalledValidator_reverts(uint256 seed) public {
        MockValidator v = new MockValidator();
        ValidationId vId = validatorToIdentifier(v);

        vm.startPrank(address(ep));
        vm.expectRevert(abi.encodeWithSelector(InvalidVid.selector, vId));
        kernel.setRoot(vId);
        vm.stopPrank();
    }

    /// @dev setRoot rejects arbitrary callers
    function testFuzz_setRoot_unauthorizedCaller_reverts(address caller) public {
        vm.assume(caller != address(ep));
        vm.assume(caller != address(kernel));

        ValidationId vId = validatorToIdentifier(secondValidator);
        vm.startPrank(caller);
        vm.expectRevert(Unauthorized.selector);
        kernel.setRoot(vId);
        vm.stopPrank();
    }

    // ========= grantAccess fuzz tests =========

    /// @dev grantAccess with non-4-byte-aligned data reverts
    function testFuzz_grantAccess_nonAlignedData_reverts(bytes calldata data) public {
        vm.assume(data.length % 4 != 0);
        ValidationId vId = validatorToIdentifier(secondValidator);

        vm.startPrank(address(ep));
        vm.expectRevert(InvalidDataLength.selector);
        kernel.grantAccess(vId, data);
        vm.stopPrank();
    }

    /// @dev grantAccess with valid aligned data increments nonce
    function testFuzz_grantAccess_alignedData_incrementsNonce(uint256 selectorCount) public {
        selectorCount = bound(selectorCount, 0, 10);
        bytes memory selectors = new bytes(selectorCount * 4);
        for (uint256 i = 0; i < selectorCount * 4; i++) {
            selectors[i] = bytes1(uint8(i));
        }
        ValidationId vId = validatorToIdentifier(secondValidator);
        ValidationInfo memory infoBefore = kernel.validationInfo(vId);
        uint32 nonceBefore = infoBefore.nonce;

        vm.startPrank(address(ep));
        kernel.grantAccess(vId, selectors);
        vm.stopPrank();

        ValidationInfo memory infoAfter = kernel.validationInfo(vId);
        assertEq(infoAfter.nonce, nonceBefore + 1, "nonce not incremented");
    }

    // ========= Nonce fuzz tests =========

    /// @dev setNonce with strictly increasing seq succeeds
    function testFuzz_setNonce_strictlyIncreasing(uint192 key, uint64 seq) public {
        key = uint192(bound(uint256(key), 0, 100));
        uint64 currentSeq = uint64(kernel.nonce(key));
        seq = uint64(bound(uint256(seq), uint256(currentSeq) + 1, type(uint64).max - 1));

        vm.startPrank(address(ep));
        kernel.setNonce(key, seq);
        vm.stopPrank();
    }

    /// @dev setValidNonceFrom with strictly increasing seq succeeds
    function testFuzz_setValidNonceFrom_strictlyIncreasing(uint64 seq) public {
        uint64 current = kernel.validNonceFrom();
        seq = uint64(bound(uint256(seq), uint256(current) + 1, type(uint64).max - 1));

        vm.startPrank(address(ep));
        kernel.setValidNonceFrom(seq);
        vm.stopPrank();

        assertEq(kernel.validNonceFrom(), seq, "validNonceFrom not updated");
    }

    // ========= executeFromExecutor fuzz tests =========

    /// @dev Uninstalled executor always gets reverted
    function testFuzz_executeFromExecutor_uninstalled_reverts(address randomExecutor) public {
        vm.assume(randomExecutor != address(executor));
        vm.assume(!kernel.isModuleInstalled(2, randomExecutor, hex""));

        bytes32 mode = bytes32(
            abi.encodePacked(LibERC7579.CALLTYPE_SINGLE, LibERC7579.EXECTYPE_TRY, bytes4(0), bytes4(0), bytes22(0))
        );
        bytes memory executionData = abi.encodePacked(address(kernel), uint256(0), abi.encodeCall(Kernel.accountId, ()));

        vm.startPrank(randomExecutor);
        vm.expectRevert(Unauthorized.selector);
        kernel.executeFromExecutor(mode, executionData);
        vm.stopPrank();
    }

    /// @dev Installed executor can execute single calls
    function testFuzz_executeFromExecutor_installed_succeeds() public {
        bytes32 mode = bytes32(
            abi.encodePacked(LibERC7579.CALLTYPE_SINGLE, LibERC7579.EXECTYPE_TRY, bytes4(0), bytes4(0), bytes22(0))
        );
        bytes memory executionData = abi.encodePacked(address(kernel), uint256(0), abi.encodeCall(Kernel.accountId, ()));

        vm.prank(address(executor));
        bytes[] memory ret = kernel.executeFromExecutor(mode, executionData);
        assertEq(ret.length, 1, "should return one result");
    }

    // ========= supportsExecutionMode fuzz tests =========

    /// @dev supportsExecutionMode returns true only for valid combinations
    function testFuzz_supportsExecutionMode(bytes32 mode) public view {
        bytes1 callType = LibERC7579.getCallType(mode);
        bytes1 execType = LibERC7579.getExecType(mode);
        bool supported = kernel.supportsExecutionMode(mode);

        bool validExecType = (execType == LibERC7579.EXECTYPE_DEFAULT || execType == LibERC7579.EXECTYPE_TRY);
        bool validCallType =
            (callType == LibERC7579.CALLTYPE_SINGLE || callType == LibERC7579.CALLTYPE_BATCH
                || callType == LibERC7579.CALLTYPE_DELEGATECALL);

        assertEq(supported, validExecType && validCallType, "supportsExecutionMode mismatch");
    }

    // ========= supportsModule fuzz tests =========

    /// @dev supportsModule returns true only for types 1, 2, 3, 5, 6, and 11
    function testFuzz_supportsModule(uint256 moduleTypeId) public view {
        bool supported = kernel.supportsModule(moduleTypeId);
        bool expected = moduleTypeId == 1 || moduleTypeId == 2 || moduleTypeId == 3 || moduleTypeId == 5
            || moduleTypeId == 6 || moduleTypeId == 11;
        assertEq(supported, expected, "supportsModule mismatch");
    }

    // ========= ERC721/1155 receiver fuzz tests =========

    /// @dev ERC721 onReceived returns correct selector
    function testFuzz_onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data) public {
        bytes memory callData = abi.encodeWithSelector(0x150b7a02, operator, from, tokenId, data);
        (bool success, bytes memory ret) = address(kernel).call(callData);
        assertTrue(success, "onERC721Received should succeed");
        assertEq(bytes4(ret), bytes4(0x150b7a02), "wrong return selector");
    }

    /// @dev ERC1155 onReceived returns correct selector
    function testFuzz_onERC1155Received(address operator, address from, uint256 id, uint256 value, bytes calldata data)
        public
    {
        bytes memory callData = abi.encodeWithSelector(0xf23a6e61, operator, from, id, value, data);
        (bool success, bytes memory ret) = address(kernel).call(callData);
        assertTrue(success, "onERC1155Received should succeed");
        assertEq(bytes4(ret), bytes4(0xf23a6e61), "wrong return selector");
    }

    // ========= Uninstall root validator fuzz tests =========

    /// @dev Cannot uninstall the current root validator
    function testFuzz_cannotUninstallRootValidator(uint256 seed) public {
        vm.startPrank(address(ep));
        vm.expectRevert(CannotUninstallRoot.selector);
        kernel.uninstallModule(1, address(rootValidator), abi.encode(hex"", hex""));
        vm.stopPrank();
    }

    // ========= OccupiedValidationId fuzz test =========

    /// @dev Installing the same validator twice reverts with OccupiedValidationId
    function testFuzz_installValidator_twice_reverts() public {
        MockValidator v = new MockValidator();
        vm.startPrank(address(ep));
        kernel.installModule(1, address(v), abi.encode(hex"", hex""));
        vm.expectRevert(OccupiedValidationId.selector);
        kernel.installModule(1, address(v), abi.encode(hex"", hex""));
        vm.stopPrank();
    }
}
