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
    CannotUninstallRoot,
    OccupiedValidationId,
    PermissionInstallNotFinished,
    Unauthorized,
    InvalidPermissionInstall,
    InvalidCallType,
    InvalidVid
} from "src/types/Error.sol";
import {
    HOOK_MODULE_NOT_INSTALLED,
    HOOK_MODULE_INSTALLED_NO_HOOK,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_HOOK,
    MODULE_TYPE_POLICY,
    MODULE_TYPE_SIGNER,
    CALLTYPE_SINGLE,
    CALLTYPE_DELEGATECALL,
    ERC1271_MAGICVALUE,
    SELECTOR_MANAGER_STORAGE_SLOT
} from "src/types/Constants.sol";
import {validatorToIdentifier, permissionToIdentifier} from "src/lib/Utils.sol";
import {IValidator, IHook, IExecutor} from "src/interfaces/IERC7579Modules.sol";
import {IERC7579Account} from "src/interfaces/IERC7579Account.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";

contract RevertPathsTest is Test {
    IEntryPoint ep;
    KernelFactory factory;
    KernelUUPS uups;
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
        uups = new KernelUUPS(ep);
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
        permissionId = PermissionId.wrap(bytes4(keccak256(abi.encodePacked("TestPermission"))));

        // Deploy kernel with root validator
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({
            moduleType: MODULE_TYPE_VALIDATOR, module: address(rootValidator), moduleData: hex"", internalData: hex""
        });
        kernel = factory.deploy(pkgs, 0);
        vm.deal(address(kernel), 1e18);
    }

    // =========================================================================
    // 3.10 - CannotUninstallRoot
    // =========================================================================

    function test_uninstallModule_WhenTargetIsRootValidator_ShouldRevertWithCannotUninstallRoot() public {
        // Arrange: rootValidator is the root
        ValidationId rootVid = kernel.root();
        assertTrue(rootVid == validatorToIdentifier(IValidator(address(rootValidator))));

        // Act & Assert: attempt to uninstall root validator
        vm.prank(address(ep));
        vm.expectRevert(CannotUninstallRoot.selector);
        kernel.uninstallModule(MODULE_TYPE_VALIDATOR, address(rootValidator), abi.encode(hex"", hex""));
    }

    // =========================================================================
    // 3.11 - OccupiedValidationId
    // =========================================================================

    function test_installModule_WhenValidationIdAlreadyOccupied_ShouldRevertWithOccupiedValidationId() public {
        // Arrange: install a validator
        vm.startPrank(address(ep));
        kernel.installModule(MODULE_TYPE_VALIDATOR, address(newValidator), abi.encode(hex"deadbeef", hex""));

        // Verify it's installed
        ValidationId vId = validatorToIdentifier(IValidator(address(newValidator)));
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.hook != HOOK_MODULE_NOT_INSTALLED);

        // Act & Assert: try to install the SAME validator again (same ValidationId) without uninstalling
        vm.expectRevert(OccupiedValidationId.selector);
        kernel.installModule(MODULE_TYPE_VALIDATOR, address(newValidator), abi.encode(hex"cafecafe", hex""));
        vm.stopPrank();
    }

    // =========================================================================
    // 3.12 - PermissionInstallNotFinished
    // =========================================================================

    function test_installModule_WhenBatchInstallsPolicyButNoSigner_ShouldRevertWithPermissionInstallNotFinished()
        public
    {
        // Arrange: create a batch with only policy (no signer)
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({
            moduleType: MODULE_TYPE_POLICY,
            module: address(policy),
            moduleData: hex"deadbeef",
            internalData: abi.encodePacked(permissionId)
        });

        // Act & Assert
        vm.prank(address(ep));
        vm.expectRevert(PermissionInstallNotFinished.selector);
        kernel.installModule(pkgs);
    }

    // =========================================================================
    // 3.13 - ERC-6492 unwrap
    // =========================================================================

    function test_isValidSignature_WhenSignatureHasERC6492Wrapper_ShouldUnwrapAndValidate() public {
        // Arrange: install newValidator
        vm.prank(address(ep));
        kernel.installModule(MODULE_TYPE_VALIDATOR, address(newValidator), abi.encode(hex"deadbeef", hex""));

        bytes32 hashToSign = keccak256("Hello ERC6492");

        // Build inner signature: mode(1) + type(1) + validator(20) + validatorSig
        // First set the valid sig on the mock
        newValidator.sudoSetValidSig(hex"aabbccdd");
        bytes memory innerSig = abi.encodePacked(bytes1(0x00), bytes1(0x01), address(newValidator), hex"aabbccdd");

        // ERC-6492 sentinel = 0x6492...6492
        // The sentinel is: mul(0x6492, div(not(shr(address(), address())), 0xffff))
        // In the contract, it checks: calldataload(add(result.offset, sub(result.length, 0x20)))
        // For the unwrap to work, the last 32 bytes must be the sentinel.
        // The format is: abi.encode(address, bytes, bytes) + sentinel
        // Where the wrapped signature = abi.encode(factoryAddr, factoryCalldata, innerSig) ++ sentinel

        // Build the ERC-6492 wrapped signature:
        // The _erc1271UnwrapSignature checks if the last 32 bytes equal the sentinel.
        // If so, it reads offset at position [0x40] to find the inner signature.
        // Format: abi.encode(address(0), bytes(""), innerSig) + sentinel
        bytes32 sentinel = _computeERC6492Sentinel(address(kernel));
        bytes memory wrapped = abi.encodePacked(abi.encode(address(0), hex"", innerSig), sentinel);

        // Act
        bytes4 result = kernel.isValidSignature(hashToSign, wrapped);

        // Assert: should validate successfully after unwrapping
        assertEq(result, ERC1271_MAGICVALUE, "ERC-6492 unwrap should work and validate signature");
    }

    function _computeERC6492Sentinel(address account) internal pure returns (bytes32) {
        // Replicates: mul(0x6492, div(not(shr(address(), address())), 0xffff))
        // shr(address, address) => shr(uint160(account), uint160(account))
        // But in EVM this is: shr(addr, addr) where addr is treated as shift amount
        // Since address is 160 bits, shr(160_bit_value, 160_bit_value) for most addresses
        // is just 0 (since shift amount >= 256 most likely not, but address is < 256)
        // Actually: shr(address(), address()) in assembly means shift right by `address()` bits
        // address() returns uint160 of the contract address
        // For a typical address like 0x1234..., the shift is by that many bits
        // not(shr(a, a)): if a > 255, shr(a,a) = 0, so not(0) = type(uint256).max
        // div(type(uint256).max, 0xffff) = type(uint256).max / 65535
        // mul(0x6492, type(uint256).max / 65535) = 0x6492 * (2^256-1)/65535
        // Since 65535 = 0xffff, and 0x6492 * x where x = not(0) / 0xffff
        // This simplifies to: 0x6492649264926492...6492
        // The sentinel is 0x6492649264926492649264926492649264926492649264926492649264926492
        return bytes32(0x6492649264926492649264926492649264926492649264926492649264926492);
    }

    // =========================================================================
    // 3.14 - _authorizeUpgrade unauthorized
    // =========================================================================

    function test_upgradeToAndCall_WhenCallerIsNotEntryPointOrSelf_ShouldRevertWithUnauthorized() public {
        // Arrange
        KernelUUPS newImpl = new KernelUUPS(ep);
        address randomCaller = makeAddr("RandomCaller");

        // Act & Assert
        vm.prank(randomCaller);
        vm.expectRevert(Unauthorized.selector);
        KernelUUPS(payable(address(kernel))).upgradeToAndCall(address(newImpl), hex"");
    }

    function test_upgradeToAndCall_WhenCallerIsEntryPoint_ShouldSucceed() public {
        // Arrange
        KernelUUPS newImpl = new KernelUUPS(ep);

        // Act: entrypoint should be allowed
        vm.prank(address(ep));
        KernelUUPS(payable(address(kernel))).upgradeToAndCall(address(newImpl), hex"");

        // Assert: upgrade succeeded (just verifying no revert)
    }

    // =========================================================================
    // 3.15 - InvalidPermissionInstall (mismatched permissionId in batch)
    // =========================================================================

    function test_installModule_WhenPolicyHasDifferentPermissionId_ShouldRevertWithInvalidPermissionInstall() public {
        // Arrange: batch with two policies for different permission IDs
        PermissionId permIdA = PermissionId.wrap(bytes4(0xaaaaaaaa));
        PermissionId permIdB = PermissionId.wrap(bytes4(0xbbbbbbbb));

        Install[] memory pkgs = new Install[](2);
        pkgs[0] = Install({
            moduleType: MODULE_TYPE_POLICY,
            module: address(policy),
            moduleData: hex"deadbeef",
            internalData: abi.encodePacked(permIdA)
        });
        // Second policy uses different permissionId
        MockPolicy policy2 = new MockPolicy();
        pkgs[1] = Install({
            moduleType: MODULE_TYPE_POLICY,
            module: address(policy2),
            moduleData: hex"deadbeef",
            internalData: abi.encodePacked(permIdB)
        });

        // Act & Assert
        vm.prank(address(ep));
        vm.expectRevert(InvalidPermissionInstall.selector);
        kernel.installModule(pkgs);
    }

    // =========================================================================
    // 3.16 - Executor with real hook
    // =========================================================================

    function test_executorWithHook_WhenExecutorInstalledWithHook_ShouldRunHookOnExecution() public {
        vm.startPrank(address(ep));

        // Step 1: Install hook
        kernel.installModule(MODULE_TYPE_HOOK, address(hook), abi.encode(hex"deadbeef", ""));

        // Step 2: Install executor referencing the hook
        kernel.installModule(
            MODULE_TYPE_EXECUTOR, address(mockExecutor), abi.encode(hex"deadbeef", abi.encodePacked(address(hook)))
        );
        vm.stopPrank();

        // Verify executor config has the hook
        ExecutorConfig memory config = kernel.executorConfig(address(mockExecutor));
        assertEq(address(config.hook), address(hook), "Executor config should reference the hook");

        // Step 3: Execute from executor and verify hook runs
        // Before execution, hook pre/post should not have been called yet
        assertFalse(hook.preHookCalled(), "Pre-hook should not have been called yet");
        assertFalse(hook.postHookCalled(), "Post-hook should not have been called yet");

        // Execute via the executor
        vm.prank(address(mockExecutor));
        kernel.executeFromExecutor(bytes32(0), abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector));

        // Assert: hook was called
        assertTrue(hook.preHookCalled(), "Pre-hook should have been called");
        assertTrue(hook.postHookCalled(), "Post-hook should have been called");
        assertEq(callee.bar(), 1, "Callee should have been called");
    }

    // =========================================================================
    // 3.17 - InvalidCallType in fallback
    // =========================================================================

    function test_fallback_WhenCallTypeIsInvalid_ShouldRevertWithInvalidCallType() public {
        // The InvalidCallType revert at Kernel.sol:232 happens in _fallback() when
        // $.callType is neither CALLTYPE_SINGLE nor CALLTYPE_DELEGATECALL.
        //
        // Normally the _installSelector function only writes what you give it, so
        // we need to use vm.store to set a bad callType in storage.

        bytes4 testSelector = MockFallback.testFunction.selector;

        // First install fallback normally
        vm.prank(address(ep));
        kernel.installModule(
            MODULE_TYPE_FALLBACK,
            address(mockFallback),
            abi.encode(
                hex"deadbeef",
                abi.encodePacked(
                    testSelector,
                    bytes1(0x00), // CALLTYPE_SINGLE
                    address(0) // no hook, will be set to address(0)
                )
            )
        );

        // Verify fallback is installed
        SelectorConfig memory config = kernel.selectorConfig(testSelector);
        assertEq(config.target, address(mockFallback));

        // Now corrupt the callType in storage to an invalid value
        // SelectorConfig layout: hook (20 bytes) | target (20 bytes) | callType (1 byte)
        // SelectorStorage is at SELECTOR_MANAGER_STORAGE_SLOT, mapped by bytes4 selector
        // Slot = keccak256(abi.encode(selector, SELECTOR_MANAGER_STORAGE_SLOT))
        bytes32 selectorSlot = keccak256(abi.encode(bytes32(testSelector), SELECTOR_MANAGER_STORAGE_SLOT));

        // The SelectorConfig is stored across two slots:
        // slot 0: hook (address, 20 bytes, right-aligned in slot)
        // slot 1: target (address, 20 bytes) | callType (bytes1, 1 byte)
        // target is in the low 20 bytes of slot+1, callType is in byte 20
        bytes32 slot1 = bytes32(uint256(selectorSlot) + 1);
        bytes32 currentVal = vm.load(address(kernel), slot1);

        // Clear and set a bad callType (0x02, which is neither 0x00 nor 0xFF)
        // The layout for slot1: [unused bytes][callType 1byte][target 20bytes]
        // Solidity stores: bytes1 callType at offset 20 from right (byte 20)
        // Actually, packed storage: address target = low 160 bits, CallType callType = next 8 bits
        // So callType is at bit 160 to 167
        // Set callType to 0x02 (invalid - neither CALLTYPE_SINGLE=0x00 nor CALLTYPE_DELEGATECALL=0xFF)
        uint256 val = uint256(currentVal);
        // Clear the callType byte (bits 160-167)
        val = val & ~(uint256(0xFF) << 160);
        // Set callType to 0x02
        val = val | (uint256(0x02) << 160);
        vm.store(address(kernel), slot1, bytes32(val));

        // Act & Assert: calling the fallback selector should revert with InvalidCallType
        // We need to call from entrypoint since hook is address(0) which means HOOK_MODULE_NOT_INSTALLED
        // and the fallback requires either target != 0 AND (hook != NOT_INSTALLED OR sender == entrypoint)
        vm.prank(address(ep));
        vm.expectRevert(InvalidCallType.selector);
        MockFallback(address(kernel)).testFunction();
    }

    // =========================================================================
    // 3.18 - Enable+replayable UserOp
    // =========================================================================

    function test_processUserOp_WhenEnableReplayableBitSet_ShouldProcessReplayableEnable() public {
        // Arrange: Build a UserOp with isEnableReplayable bit set
        // vMode bits: bit 6 = replayable userOp, bit 3 = enable, bit 2 = replayable enable
        // For enable+replayable enable: 0x08 | 0x04 = 0x0C
        // The nonce key encodes: mode(1 byte) | type(1 byte) | vId(20 bytes) | 2 byte padding

        MockValidator enabledValidator = new MockValidator();

        // Build the enable packages
        Install[] memory packages = new Install[](1);
        packages[0] = Install({
            moduleType: MODULE_TYPE_VALIDATOR,
            module: address(enabledValidator),
            moduleData: hex"",
            internalData: abi.encodePacked(address(0), Kernel.execute.selector)
        });

        // Compute the enable signature digest (replayable = true)
        bytes32 digest = KernelHelper.installDigest(address(kernel), true, 0, packages);
        // Set root validator to accept
        rootValidator.sudoSetValidSig(hex"");

        // Compute the nonce: enable+replayable enable for validator type
        // mode = 0x0C (enable=0x08, replayableEnable=0x04), type = 0x01 (validator), vId = enabledValidator
        uint8 uMode = 0x08 + 0x04; // enable + replayable enable = 0x0C
        uint192 key =
            uint192(bytes24(abi.encodePacked(uMode, bytes1(0x01), bytes20(address(enabledValidator)), bytes2(0x0000))));
        uint256 nonce = ep.getNonce(address(kernel), key);

        // Set the enabled validator to accept the userOp
        enabledValidator.sudoSetSuccess(true);

        // Encode the enable signature
        bytes memory enableSig = hex""; // root validator accepts empty sig when sudoSetValidSig(hex"") is set
        bytes memory userOpSig = hex""; // enabled validator accepts when sudoSetSuccess(true)
        bytes memory fullSig = abi.encode(uint256(0), packages, enableSig, userOpSig);

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

        // Act
        vm.startPrank(beneficiary, beneficiary);
        ep.handleOps(ops, beneficiary);
        vm.stopPrank();

        // Assert: the operation succeeded
        assertEq(callee.bar(), 1, "Callee.foo() should have been called");
        // The validator should now be installed
        ValidationInfo memory vInfo =
            kernel.validationInfo(validatorToIdentifier(IValidator(address(enabledValidator))));
        assertEq(vInfo.hook, HOOK_MODULE_INSTALLED_NO_HOOK, "Enabled validator should be installed");
    }
}
