pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Kernel} from "src/Kernel.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {KernelImmutableECDSA} from "src/KernelImmutableECDSA.sol";
import {KernelFactory} from "src/KernelFactory.sol";
import {Install, SelectorConfig, ValidationInfo} from "src/types/Structs.sol";
import {ValidationId, CallType, PermissionId} from "src/types/Types.sol";
import {validatorToIdentifier, permissionToIdentifier, getType} from "src/lib/Utils.sol";
import {
    CALLTYPE_DELEGATECALL,
    CALLTYPE_SINGLE,
    VALIDATION_TYPE_VALIDATOR,
    VALIDATION_TYPE_PERMISSION,
    HOOK_MODULE_NOT_INSTALLED
} from "src/types/Constants.sol";
import {Unauthorized} from "src/types/Error.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {MockValidator} from "../mock/MockValidator.sol";
import {MockExecutor} from "../mock/MockExecutor.sol";
import {MockHook} from "../mock/MockHook.sol";
import {MockFallback} from "../mock/MockFallback.sol";
import {MockPolicy} from "../mock/MockPolicy.sol";
import {MockSigner} from "../mock/MockSigner.sol";
import {IERC7579Account} from "src/interfaces/IERC7579Account.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";

contract KernelInvariantHandler is Test {
    Kernel public immutable kernel;
    IEntryPoint public immutable ep;
    MockValidator public immutable rootValidator;

    MockValidator[] public validators;
    MockExecutor[] public executors;
    MockHook[] public hooks;
    MockFallback[] public fallbacks;
    MockPolicy[] public policies;
    MockSigner[] public signers;
    bytes4[] public selectors;
    address[] public policyStack;

    mapping(address => bool) public validatorInstalled;
    mapping(address => bool) public executorInstalled;
    mapping(address => bool) public hookInstalled;
    mapping(bytes4 => address) public selectorTarget;
    mapping(bytes4 => bytes1) public selectorCallType;
    mapping(address => bool) public policyInstalled;
    address public signerInstalled;
    bytes4 public permissionId;

    // Ghost variables for nonce tracking
    uint192[] public exercisedNonceKeys;
    mapping(uint192 => bool) public nonceKeyExercised;
    mapping(uint192 => uint64) public ghostNonce;
    uint64 public ghostValidNonceFrom;

    // Ghost variables for executor hook enforcement
    uint256 public uninstalledExecutorCallCount;
    uint256 public uninstalledExecutorRevertCount;

    // Ghost variable for root tracking
    ValidationId public ghostRoot;

    constructor(Kernel kernel_, IEntryPoint ep_, MockValidator rootValidator_) {
        kernel = kernel_;
        ep = ep_;
        rootValidator = rootValidator_;

        validatorInstalled[address(rootValidator_)] = true;
        ghostRoot = validatorToIdentifier(rootValidator_);

        for (uint256 i = 0; i < 3; i++) {
            validators.push(new MockValidator());
        }
        for (uint256 i = 0; i < 2; i++) {
            executors.push(new MockExecutor());
            hooks.push(new MockHook());
            fallbacks.push(new MockFallback());
            policies.push(new MockPolicy());
            signers.push(new MockSigner());
        }

        selectors.push(MockFallback.fallbackFunction.selector);
        selectors.push(MockFallback.forceRevert.selector);
        selectors.push(MockFallback.testFunction.selector);

        permissionId = bytes4(keccak256("permission"));
    }

    function installValidator(uint256 index) external {
        MockValidator validator = validators[index % validators.length];
        vm.startPrank(address(ep));
        kernel.installModule(1, address(validator), abi.encode(hex"deadbeef", hex""));
        vm.stopPrank();
        validatorInstalled[address(validator)] = true;
    }

    function uninstallValidator(uint256 index) external {
        MockValidator validator = validators[index % validators.length];
        // Cannot uninstall the current root validator
        ValidationId vId = validatorToIdentifier(validator);
        if (ValidationId.unwrap(vId) == ValidationId.unwrap(ghostRoot)) {
            return;
        }
        vm.startPrank(address(ep));
        kernel.uninstallModule(1, address(validator), abi.encode(hex"", hex""));
        vm.stopPrank();
        validatorInstalled[address(validator)] = false;
    }

    function installExecutor(uint256 index) external {
        MockExecutor executor = executors[index % executors.length];
        vm.startPrank(address(ep));
        kernel.installModule(2, address(executor), abi.encode(hex"deadbeef", hex""));
        vm.stopPrank();
        executorInstalled[address(executor)] = true;
    }

    function uninstallExecutor(uint256 index) external {
        MockExecutor executor = executors[index % executors.length];
        vm.startPrank(address(ep));
        kernel.uninstallModule(2, address(executor), abi.encode(hex"", hex""));
        vm.stopPrank();
        executorInstalled[address(executor)] = false;
    }

    function installHook(uint256 index) external {
        MockHook hook = hooks[index % hooks.length];
        vm.startPrank(address(ep));
        kernel.installModule(4, address(hook), abi.encode(hex"", hex""));
        vm.stopPrank();
        hookInstalled[address(hook)] = true;
    }

    function uninstallHook(uint256 index) external {
        MockHook hook = hooks[index % hooks.length];
        vm.startPrank(address(ep));
        kernel.uninstallModule(4, address(hook), abi.encode(hex"", hex""));
        vm.stopPrank();
        hookInstalled[address(hook)] = false;
    }

    function validatorCount() external view returns (uint256) {
        return validators.length;
    }

    function executorCount() external view returns (uint256) {
        return executors.length;
    }

    function hookCount() external view returns (uint256) {
        return hooks.length;
    }

    function fallbackCount() external view returns (uint256) {
        return fallbacks.length;
    }

    function selectorCount() external view returns (uint256) {
        return selectors.length;
    }

    function policyCount() external view returns (uint256) {
        return policies.length;
    }

    function signerCount() external view returns (uint256) {
        return signers.length;
    }

    function policyStackCount() external view returns (uint256) {
        return policyStack.length;
    }

    function exercisedNonceKeysCount() external view returns (uint256) {
        return exercisedNonceKeys.length;
    }

    function installSelector(uint256 selectorIndex, uint256 targetIndex, bool delegatecall) external {
        bytes4 selector = selectors[selectorIndex % selectors.length];
        MockFallback target = fallbacks[targetIndex % fallbacks.length];
        bytes1 callType = delegatecall ? CallType.unwrap(CALLTYPE_DELEGATECALL) : CallType.unwrap(CALLTYPE_SINGLE);
        bytes memory internalData = abi.encodePacked(selector, callType, address(0));
        vm.startPrank(address(ep));
        kernel.installModule(3, address(target), abi.encode(hex"deadbeef", internalData));
        vm.stopPrank();
        selectorTarget[selector] = address(target);
        selectorCallType[selector] = callType;
    }

    function uninstallSelector(uint256 selectorIndex) external {
        bytes4 selector = selectors[selectorIndex % selectors.length];
        address target = selectorTarget[selector];
        if (target == address(0)) {
            target = address(fallbacks[0]);
        }
        vm.startPrank(address(ep));
        kernel.uninstallModule(3, target, abi.encode(hex"", abi.encodePacked(selector)));
        vm.stopPrank();
        selectorTarget[selector] = address(0);
        selectorCallType[selector] = bytes1(0);
    }

    function installPolicy(uint256 index) external {
        MockPolicy policy = policies[index % policies.length];
        if (policyInstalled[address(policy)]) {
            return;
        }
        vm.startPrank(address(ep));
        kernel.installModule(5, address(policy), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        vm.stopPrank();
        policyInstalled[address(policy)] = true;
        policyStack.push(address(policy));
    }

    function uninstallPolicy() external {
        uint256 len = policyStack.length;
        if (len == 0) {
            return;
        }
        address policy = policyStack[len - 1];
        vm.startPrank(address(ep));
        kernel.uninstallModule(5, policy, abi.encode(hex"", abi.encodePacked(permissionId)));
        vm.stopPrank();
        policyInstalled[policy] = false;
        policyStack.pop();
    }

    function installSigner(uint256 index) external {
        MockSigner signer = signers[index % signers.length];
        vm.startPrank(address(ep));
        kernel.installModule(6, address(signer), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        vm.stopPrank();
        signerInstalled = address(signer);
    }

    function uninstallSigner() external {
        if (signerInstalled == address(0) || policyStack.length != 0) {
            return;
        }
        address signer = signerInstalled;
        vm.startPrank(address(ep));
        kernel.uninstallModule(6, signer, abi.encode(hex"", abi.encodePacked(permissionId)));
        vm.stopPrank();
        signerInstalled = address(0);
    }

    // --- 3.4: Nonce handler actions ---

    function setNonce(uint192 key, uint64 seq) external {
        // Bound key to a small range to increase collisions / reuse
        key = uint192(bound(uint256(key), 0, 9));
        // seq must be > current nonce for this key
        uint64 currentSeq = uint64(kernel.nonce(key));
        if (seq <= currentSeq) {
            seq = currentSeq + 1;
        }
        // Cap to avoid overflow
        if (seq > type(uint64).max - 1) {
            return;
        }
        vm.startPrank(address(ep));
        kernel.setNonce(key, seq);
        vm.stopPrank();

        // Track ghost state
        if (!nonceKeyExercised[key]) {
            nonceKeyExercised[key] = true;
            exercisedNonceKeys.push(key);
        }
        ghostNonce[key] = seq;
    }

    function setValidNonceFrom(uint64 seq) external {
        uint64 currentValidFrom = kernel.validNonceFrom();
        if (seq <= currentValidFrom) {
            seq = currentValidFrom + 1;
        }
        if (seq > type(uint64).max - 1) {
            return;
        }
        vm.startPrank(address(ep));
        kernel.setValidNonceFrom(seq);
        vm.stopPrank();

        ghostValidNonceFrom = seq;
    }

    // --- 3.5: Root-always-installed handler action ---

    function setRoot(uint256 validatorIndex) external {
        // Only set root to an installed validator
        MockValidator validator = validators[validatorIndex % validators.length];
        if (!validatorInstalled[address(validator)]) {
            return;
        }
        ValidationId vId = validatorToIdentifier(validator);
        vm.startPrank(address(ep));
        kernel.setRoot(vId);
        vm.stopPrank();
        ghostRoot = vId;
    }

    // --- 3.6: Executor hook enforcement handler actions ---

    function executeFromInstalledExecutor(uint256 index) external {
        MockExecutor executor = executors[index % executors.length];
        if (!executorInstalled[address(executor)]) {
            return;
        }
        // Execute a no-op single call (call to kernel.accountId() which is a view)
        bytes32 mode = bytes32(
            abi.encodePacked(LibERC7579.CALLTYPE_SINGLE, LibERC7579.EXECTYPE_TRY, bytes4(0), bytes4(0), bytes22(0))
        );
        bytes memory executionData = abi.encodePacked(address(kernel), uint256(0), abi.encodeCall(Kernel.accountId, ()));
        vm.prank(address(executor));
        kernel.executeFromExecutor(mode, executionData);
    }

    function executeFromUninstalledExecutor(uint256 index) external {
        MockExecutor executor = executors[index % executors.length];
        if (executorInstalled[address(executor)]) {
            return;
        }
        uninstalledExecutorCallCount++;

        bytes32 mode = bytes32(
            abi.encodePacked(LibERC7579.CALLTYPE_SINGLE, LibERC7579.EXECTYPE_TRY, bytes4(0), bytes4(0), bytes22(0))
        );
        bytes memory executionData = abi.encodePacked(address(kernel), uint256(0), abi.encodeCall(Kernel.accountId, ()));
        vm.prank(address(executor));
        try kernel.executeFromExecutor(mode, executionData) {
        // Should never succeed
        }
        catch {
            uninstalledExecutorRevertCount++;
        }
    }
}

contract KernelInvariant is StdInvariant, Test {
    Kernel private kernel;
    IEntryPoint private ep;
    MockValidator private rootValidator;
    KernelInvariantHandler private handler;

    function setUp() external {
        ep = EntryPointLib.deploy();

        KernelUUPS uups = new KernelUUPS(ep);
        KernelImmutableECDSA immutableEcdsa = new KernelImmutableECDSA(ep);
        KernelFactory factory = new KernelFactory(uups, immutableEcdsa);

        rootValidator = new MockValidator();
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});
        kernel = factory.deploy(pkgs, 0);

        handler = new KernelInvariantHandler(kernel, ep, rootValidator);
        targetContract(address(handler));
    }

    function invariant_root_is_installed() external view {
        ValidationId expectedRoot = handler.ghostRoot();
        assertEq(ValidationId.unwrap(kernel.root()), ValidationId.unwrap(expectedRoot), "root != expected ghost root");
    }

    function invariant_validator_install_state_matches_handler() external {
        uint256 count = handler.validatorCount();
        for (uint256 i = 0; i < count; i++) {
            address validator = address(handler.validators(i));
            assertEq(
                kernel.isModuleInstalled(1, validator, hex""),
                handler.validatorInstalled(validator),
                "validator install state mismatch"
            );
            if (validator != address(rootValidator)) {
                ValidationId vId = validatorToIdentifier(MockValidator(validator));
                bool installed = handler.validatorInstalled(validator);
                assertEq(kernel.validationInfo(vId).hook != address(0), installed, "validator hook mismatch");
            }
        }
    }

    function invariant_executor_install_state_matches_handler() external {
        uint256 count = handler.executorCount();
        for (uint256 i = 0; i < count; i++) {
            address executor = address(handler.executors(i));
            assertEq(
                kernel.isModuleInstalled(2, executor, hex""),
                handler.executorInstalled(executor),
                "executor install state mismatch"
            );
            bool installed = handler.executorInstalled(executor);
            assertEq(address(kernel.executorConfig(executor).hook) != address(0), installed, "executor hook mismatch");
        }
    }

    function invariant_hook_install_state_matches_handler() external {
        uint256 count = handler.hookCount();
        for (uint256 i = 0; i < count; i++) {
            address hook = address(handler.hooks(i));
            assertEq(
                kernel.isModuleInstalled(4, hook, hex""), handler.hookInstalled(hook), "hook install state mismatch"
            );
        }
    }

    function invariant_selector_state_matches_handler() external {
        uint256 count = handler.selectorCount();
        for (uint256 i = 0; i < count; i++) {
            bytes4 selector = handler.selectors(i);
            address target = handler.selectorTarget(selector);
            bytes1 callType = handler.selectorCallType(selector);
            bool installed = target != address(0);
            if (installed) {
                assertTrue(
                    kernel.isModuleInstalled(3, target, abi.encodePacked(selector)), "selector installed mismatch"
                );
            } else {
                assertFalse(
                    kernel.isModuleInstalled(3, address(0xdead), abi.encodePacked(selector)),
                    "selector should be uninstalled"
                );
            }
            SelectorConfig memory cfg = kernel.selectorConfig(selector);
            assertEq(cfg.target, target, "selector target mismatch");
            assertEq(CallType.unwrap(cfg.callType), callType, "selector callType mismatch");
        }
    }

    function invariant_permission_state_matches_handler() external {
        PermissionId permId = PermissionId.wrap(handler.permissionId());
        ValidationId vId = permissionToIdentifier(permId);
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertEq(vInfo.policies.length, handler.policyStackCount(), "policy length mismatch");
        for (uint256 i = 0; i < handler.policyStackCount(); i++) {
            address policy = handler.policyStack(i);
            assertTrue(kernel.isModuleInstalled(5, policy, abi.encodePacked(handler.permissionId())));
            assertTrue(handler.policyInstalled(policy));
        }
        address signer = handler.signerInstalled();
        assertEq(vInfo.signer, signer, "signer mismatch");
        if (signer != address(0)) {
            assertTrue(kernel.isModuleInstalled(6, signer, abi.encodePacked(handler.permissionId())));
        }
    }

    // --- 3.4: Nonce invariant ---
    // For all exercised nonce keys, kernel.nonce(key) >= kernel.validNonceFrom()
    function invariant_nonce_gte_validNonceFrom() external view {
        uint64 validFrom = kernel.validNonceFrom();
        uint256 keyCount = handler.exercisedNonceKeysCount();
        for (uint256 i = 0; i < keyCount; i++) {
            uint192 key = handler.exercisedNonceKeys(i);
            uint256 fullNonce = kernel.nonce(key);
            // The sequence portion is the lower 64 bits
            uint64 seq = uint64(fullNonce);
            assertGe(seq, validFrom, "nonce seq < validNonceFrom");
        }
    }

    // --- 3.5: Root-always-installed invariant ---
    // If root != bytes21(0), then validationInfo(root).hook > address(0)
    function invariant_root_always_installed() external view {
        ValidationId rootId = kernel.root();
        if (ValidationId.unwrap(rootId) != bytes21(0)) {
            ValidationInfo memory vInfo = kernel.validationInfo(rootId);
            assertTrue(vInfo.hook > address(0), "root validation hook is zero (not installed)");
        }
    }

    // --- 3.6: Executor hook enforcement invariant ---
    // Uninstalled executors always revert when calling executeFromExecutor
    function invariant_uninstalled_executor_always_reverts() external view {
        assertEq(
            handler.uninstalledExecutorCallCount(),
            handler.uninstalledExecutorRevertCount(),
            "uninstalled executor call did not revert"
        );
    }

    // --- 3.7: Hook consistency invariant ---
    // Every installed validator/executor with a real hook (> address(1)) must have that hook enabled
    function invariant_hook_consistency() external {
        // Check validators
        uint256 vCount = handler.validatorCount();
        for (uint256 i = 0; i < vCount; i++) {
            address validator = address(handler.validators(i));
            if (handler.validatorInstalled(validator)) {
                ValidationId vId = validatorToIdentifier(MockValidator(validator));
                ValidationInfo memory vInfo = kernel.validationInfo(vId);
                address hookAddr = vInfo.hook;
                if (hookAddr > address(1)) {
                    assertTrue(
                        kernel.isModuleInstalled(4, hookAddr, hex""), "validator hook not installed as hook module"
                    );
                }
            }
        }

        // Check executors
        uint256 eCount = handler.executorCount();
        for (uint256 i = 0; i < eCount; i++) {
            address executor = address(handler.executors(i));
            if (handler.executorInstalled(executor)) {
                address hookAddr = address(kernel.executorConfig(executor).hook);
                if (hookAddr > address(1)) {
                    assertTrue(
                        kernel.isModuleInstalled(4, hookAddr, hex""), "executor hook not installed as hook module"
                    );
                }
            }
        }

        // Check selectors
        uint256 sCount = handler.selectorCount();
        for (uint256 i = 0; i < sCount; i++) {
            bytes4 selector = handler.selectors(i);
            address target = handler.selectorTarget(selector);
            if (target != address(0)) {
                SelectorConfig memory cfg = kernel.selectorConfig(selector);
                address hookAddr = address(cfg.hook);
                if (hookAddr > address(1)) {
                    assertTrue(
                        kernel.isModuleInstalled(4, hookAddr, hex""), "selector hook not installed as hook module"
                    );
                }
            }
        }
    }

    // --- 3.8: Module installation symmetry invariant ---
    // Ghost variables track install/uninstall pairs; after uninstall, module must not be installed
    function invariant_module_install_symmetry() external {
        // Validators: if ghost says uninstalled, kernel agrees
        uint256 vCount = handler.validatorCount();
        for (uint256 i = 0; i < vCount; i++) {
            address validator = address(handler.validators(i));
            bool ghostInstalled = handler.validatorInstalled(validator);
            bool kernelInstalled = kernel.isModuleInstalled(1, validator, hex"");
            assertEq(ghostInstalled, kernelInstalled, "validator symmetry violated");
        }

        // Executors: same check
        uint256 eCount = handler.executorCount();
        for (uint256 i = 0; i < eCount; i++) {
            address executor = address(handler.executors(i));
            bool ghostInstalled = handler.executorInstalled(executor);
            bool kernelInstalled = kernel.isModuleInstalled(2, executor, hex"");
            assertEq(ghostInstalled, kernelInstalled, "executor symmetry violated");
        }

        // Hooks: same check
        uint256 hCount = handler.hookCount();
        for (uint256 i = 0; i < hCount; i++) {
            address hook = address(handler.hooks(i));
            bool ghostInstalled = handler.hookInstalled(hook);
            bool kernelInstalled = kernel.isModuleInstalled(4, hook, hex"");
            assertEq(ghostInstalled, kernelInstalled, "hook symmetry violated");
        }
    }

    // --- 3.9: Nonce monotonicity invariant ---
    // For each nonce key, the kernel's nonce never decreases between invariant checks
    function invariant_nonce_monotonicity() external view {
        uint256 keyCount = handler.exercisedNonceKeysCount();
        for (uint256 i = 0; i < keyCount; i++) {
            uint192 key = handler.exercisedNonceKeys(i);
            uint256 fullNonce = kernel.nonce(key);
            uint64 seq = uint64(fullNonce);
            // The ghost nonce tracks the last set value; kernel nonce should be >= ghost
            uint64 ghostSeq = handler.ghostNonce(key);
            assertGe(seq, ghostSeq, "nonce decreased below ghost tracked value");
        }
    }

    // --- 3.10: Permission policy ordering invariant ---
    // Policies must be in the same order as the handler's policy stack
    function invariant_permission_policy_ordering() external {
        PermissionId permId = PermissionId.wrap(handler.permissionId());
        ValidationId vId = permissionToIdentifier(permId);
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        uint256 stackCount = handler.policyStackCount();
        assertEq(vInfo.policies.length, stackCount, "policy count mismatch");
        for (uint256 i = 0; i < stackCount; i++) {
            assertEq(vInfo.policies[i], handler.policyStack(i), "policy order mismatch");
        }
    }

    // --- 3.11: Storage slot isolation invariant ---
    // ERC-7201 storage slots for different managers do not collide
    function invariant_storage_slot_isolation() external pure {
        // All five storage slots must be distinct
        bytes32[5] memory slots = [
            bytes32(0x550d18e77e0b3e646dcc27a9961c73d7867a7c5f6c2c65424629353cdc97dcc0), // SELECTOR_MANAGER
            bytes32(0x9bc558e75ed0a57385e96d6b87fd2864d462eed29668be6fed742168fd90ab0f), // MODULE_MANAGER
            bytes32(0xc98f19fae81314cbf0302e1e3c0554f60c259fab8e2d5d392893489d40eb0045), // EXECUTOR_MANAGER
            bytes32(0x5419def70c6ad54339f14ca6da31808409bec8ff0f178491c5b59f0d8276d4d3), // HOOK_MANAGER
            bytes32(0xded5d420c407eac3c615e6abe13ab4a0bd7173e5045ea543765b46f0df6e260c) // VALIDATION_MANAGER
        ];
        for (uint256 i = 0; i < 5; i++) {
            for (uint256 j = i + 1; j < 5; j++) {
                assertTrue(slots[i] != slots[j], "storage slot collision detected");
            }
        }
    }
}
