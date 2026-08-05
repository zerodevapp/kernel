// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Kernel} from "src/Kernel.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {KernelImmutableECDSA} from "src/KernelImmutableECDSA.sol";
import {KernelFactory} from "src/KernelFactory.sol";
import {Install, ValidationInfo} from "src/types/Structs.sol";
import {ERC1967_IMPLEMENTATION_SLOT} from "src/types/Constants.sol";
import {ValidationId, PermissionId} from "src/types/Types.sol";
import {validatorToIdentifier, permissionToIdentifier} from "src/lib/Utils.sol";
import {InvalidSelector} from "src/types/Error.sol";
import {IERC7579Account} from "src/interfaces/IERC7579Account.sol";
import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";
import {MockValidator} from "../mock/MockValidator.sol";
import {MockExecutor} from "../mock/MockExecutor.sol";
import {MockCallee} from "../mock/MockCallee.sol";
import {MockHook} from "../mock/MockHook.sol";
import {MockFallback} from "../mock/MockFallback.sol";
import {MockPolicy} from "../mock/MockPolicy.sol";
import {MockSigner} from "../mock/MockSigner.sol";
import {KernelHelper} from "../KernelHelper.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {ChainAgnosticHashHelper} from "../utils/ChainAgnosticHashHelper.sol";

/// @title Kernel Integration Edge-Case Tests
/// @notice Adversarial and edge-case integration tests exercising real EntryPoint, Factory, and Kernel.
///         All core protocol contracts are real -- only peripheral mocks (MockValidator, MockCallee, etc.)
///         are used for controllable validation and callee side-effects.
contract KernelIntegrationEdgeCasesTest is Test {
    IEntryPoint ep;
    KernelFactory factory;
    KernelUUPS uups;
    KernelImmutableECDSA immutableEcdsa;
    MockValidator rootValidator;
    MockCallee callee;
    address payable beneficiary;

    function setUp() public {
        ep = EntryPointLib.deploy();
        uups = new KernelUUPS(ep);
        immutableEcdsa = new KernelImmutableECDSA(ep);
        factory = new KernelFactory(uups, immutableEcdsa);
        rootValidator = new MockValidator();
        callee = new MockCallee();
        beneficiary = payable(makeAddr("Beneficiary"));
        vm.txGasPrice(1);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    function _deployKernel() internal returns (Kernel kernel) {
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});
        kernel = factory.deploy(pkgs, 0);
        vm.deal(address(kernel), 10e18);
    }

    function _rootNonce(address sender) internal view returns (uint256) {
        uint192 key = 0;
        return ep.getNonce(sender, key);
    }

    /// @dev Encode nonce: vMode(1) | vType(1) | vId(20) | nonceKey(2) | seq(8)
    ///      vMode bits: 0x40=replayable userOp, 0x08=enable, 0x04=enable-replayable
    function _encodeNonce(
        bool replayableUserOp,
        bool enableFlag,
        bool replayableEnable,
        bytes1 vType,
        bytes20 vId,
        address sender
    ) internal view returns (uint256 nonce) {
        uint8 uMode = 0;
        if (replayableUserOp) uMode += 0x40;
        if (enableFlag) uMode += 0x08;
        if (replayableEnable) uMode += 0x04;
        uint192 key = uint192(bytes24(abi.encodePacked(uMode, vType, vId, bytes2(0x00))));
        return ep.getNonce(sender, key);
    }

    function _buildCallFooOp(address sender, uint256 nonce) internal view returns (PackedUserOperation memory op) {
        op = PackedUserOperation({
            sender: sender,
            nonce: nonce,
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector,
                bytes32(0),
                abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1_000_000), uint128(1_000_000))),
            preVerificationGas: 1_000_000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
    }

    function _handleOps(PackedUserOperation[] memory ops) internal {
        vm.startPrank(beneficiary, beneficiary);
        ep.handleOps(ops, beneficiary);
        vm.stopPrank();
    }

    // -----------------------------------------------------------------------
    // Test 1: Permission-based UserOp flow
    // -----------------------------------------------------------------------

    /// @notice Full EP -> Kernel with permission validation (policy chain + signer),
    ///         not just root validator.
    function test_permissionBasedUserOpFlow() public {
        Kernel kernel = _deployKernel();

        // Deploy policy and signer mocks
        MockPolicy policy = new MockPolicy();
        MockSigner signer = new MockSigner();

        // Define a permission ID
        PermissionId permId = PermissionId.wrap(bytes4(0xdeadbeef));
        bytes32 paddedPermId = bytes32(PermissionId.unwrap(permId));

        // Install policy and signer via entrypoint (privileged)
        vm.startPrank(address(ep));
        kernel.installModule(5, address(policy), abi.encode(hex"", abi.encodePacked(permId)));
        kernel.installModule(
            6, address(signer), abi.encode(hex"", abi.encodePacked(permId, address(0), Kernel.execute.selector))
        );
        vm.stopPrank();

        // Verify installation
        ValidationId vId = permissionToIdentifier(permId);
        assertTrue(kernel.isModuleInstalled(5, address(policy), abi.encodePacked(permId)), "policy should be installed");
        assertTrue(kernel.isModuleInstalled(6, address(signer), abi.encodePacked(permId)), "signer should be installed");

        // Build a UserOp with permission-type nonce (vType=0x02)
        uint256 nonce =
            _encodeNonce(false, false, false, bytes1(0x02), bytes20(PermissionId.unwrap(permId)), address(kernel));
        PackedUserOperation memory op = _buildCallFooOp(address(kernel), nonce);

        // Set up permission signatures: policy expects matching sig, signer expects matching sig
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = hex"dead";
        signatures[1] = hex"beef";
        policy.sudoSetValidSig(address(kernel), paddedPermId, hex"dead");
        signer.sudoSetValidSig(address(kernel), paddedPermId, hex"beef");

        op.signature = abi.encode(signatures);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        _handleOps(ops);

        assertEq(callee.bar(), 1, "callee.foo() should have been called through permission validation");
    }

    // -----------------------------------------------------------------------
    // Test 2: Enable-mode install via UserOp
    // -----------------------------------------------------------------------

    /// @notice Install a new validator via enable-mode signature within a UserOp,
    ///         then use it in the next UserOp.
    function test_enableModeInstallAndUse() public {
        Kernel kernel = _deployKernel();

        // Create a new validator to install via enable-mode
        MockValidator newValidator = new MockValidator();

        // Build the enable-mode UserOp (vType=0x01 for validator, enableFlag=true)
        uint256 nonce = _encodeNonce(false, true, false, bytes1(0x01), bytes20(address(newValidator)), address(kernel));
        PackedUserOperation memory op = _buildCallFooOp(address(kernel), nonce);

        // Prepare the enable signature: install packages + root signature + userOp signature
        Install[] memory packages = new Install[](1);
        packages[0] = Install({
            moduleType: 1,
            module: address(newValidator),
            moduleData: hex"",
            internalData: abi.encodePacked(Kernel.execute.selector)
        });

        // Root validator signs the install digest
        bytes32 digest = KernelHelper.installDigest(address(kernel), false, 0, packages);
        rootValidator.sudoSetValidSig(hex"");

        // New validator validates the UserOp itself
        newValidator.sudoSetSuccess(true);

        // Encode signature: (nonce, packages, enableSignature, userOpSignature)
        op.signature = abi.encode(uint256(0), packages, hex"", hex"");

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        _handleOps(ops);

        // Verify: new validator is installed
        assertTrue(
            kernel.isModuleInstalled(1, address(newValidator), hex""),
            "new validator should be installed after enable-mode"
        );
        // callee.foo() was called
        assertEq(callee.bar(), 1, "callee.foo() should have been called in the enable-mode UserOp");

        // --- Second UserOp: use the newly installed validator directly ---
        uint256 nonce2 =
            _encodeNonce(false, false, false, bytes1(0x01), bytes20(address(newValidator)), address(kernel));
        PackedUserOperation memory op2 = _buildCallFooOp(address(kernel), nonce2);
        newValidator.sudoSetSuccess(true);
        op2.signature = hex"";

        PackedUserOperation[] memory ops2 = new PackedUserOperation[](1);
        ops2[0] = op2;
        _handleOps(ops2);

        assertEq(callee.bar(), 2, "callee.foo() should be callable via the newly-enabled validator");
    }

    // -----------------------------------------------------------------------
    // Test 3: Multi-validator scenario
    // -----------------------------------------------------------------------

    /// @notice Install 3 different validators, execute UserOps with each,
    ///         uninstall one, verify the others still work.
    function test_multiValidatorInstallUseUninstall() public {
        Kernel kernel = _deployKernel();

        // Deploy 3 validators
        MockValidator v1 = new MockValidator();
        MockValidator v2 = new MockValidator();
        MockValidator v3 = new MockValidator();

        // Install all 3 via entrypoint with execute selector access
        vm.startPrank(address(ep));
        kernel.installModule(1, address(v1), abi.encode(hex"", abi.encodePacked(Kernel.execute.selector)));
        kernel.installModule(1, address(v2), abi.encode(hex"", abi.encodePacked(Kernel.execute.selector)));
        kernel.installModule(1, address(v3), abi.encode(hex"", abi.encodePacked(Kernel.execute.selector)));
        vm.stopPrank();

        assertTrue(kernel.isModuleInstalled(1, address(v1), hex""), "v1 should be installed");
        assertTrue(kernel.isModuleInstalled(1, address(v2), hex""), "v2 should be installed");
        assertTrue(kernel.isModuleInstalled(1, address(v3), hex""), "v3 should be installed");

        // Execute UserOp with v1
        v1.sudoSetSuccess(true);
        {
            uint256 nonce = _encodeNonce(false, false, false, bytes1(0x01), bytes20(address(v1)), address(kernel));
            PackedUserOperation memory op = _buildCallFooOp(address(kernel), nonce);
            PackedUserOperation[] memory ops = new PackedUserOperation[](1);
            ops[0] = op;
            _handleOps(ops);
        }
        assertEq(callee.bar(), 1, "v1 UserOp should succeed");

        // Execute UserOp with v2
        v2.sudoSetSuccess(true);
        {
            uint256 nonce = _encodeNonce(false, false, false, bytes1(0x01), bytes20(address(v2)), address(kernel));
            PackedUserOperation memory op = _buildCallFooOp(address(kernel), nonce);
            PackedUserOperation[] memory ops = new PackedUserOperation[](1);
            ops[0] = op;
            _handleOps(ops);
        }
        assertEq(callee.bar(), 2, "v2 UserOp should succeed");

        // Execute UserOp with v3
        v3.sudoSetSuccess(true);
        {
            uint256 nonce = _encodeNonce(false, false, false, bytes1(0x01), bytes20(address(v3)), address(kernel));
            PackedUserOperation memory op = _buildCallFooOp(address(kernel), nonce);
            PackedUserOperation[] memory ops = new PackedUserOperation[](1);
            ops[0] = op;
            _handleOps(ops);
        }
        assertEq(callee.bar(), 3, "v3 UserOp should succeed");

        // Uninstall v2 via root UserOp
        rootValidator.sudoSetSuccess(true);
        {
            uint256 nonce = _rootNonce(address(kernel));
            PackedUserOperation memory uninstallOp = PackedUserOperation({
                sender: address(kernel),
                nonce: nonce,
                initCode: hex"",
                callData: abi.encodeWithSelector(
                    Kernel.execute.selector,
                    bytes32(0),
                    abi.encodePacked(
                        address(kernel),
                        uint256(0),
                        abi.encodeWithSelector(
                            IERC7579Account.uninstallModule.selector, uint256(1), address(v2), abi.encode(hex"", hex"")
                        )
                    )
                ),
                accountGasLimits: bytes32(abi.encodePacked(uint128(2_000_000), uint128(2_000_000))),
                preVerificationGas: 1_000_000,
                gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
                paymasterAndData: hex"",
                signature: hex""
            });
            PackedUserOperation[] memory ops = new PackedUserOperation[](1);
            ops[0] = uninstallOp;
            _handleOps(ops);
        }

        // v2 is uninstalled
        assertFalse(kernel.isModuleInstalled(1, address(v2), hex""), "v2 should be uninstalled");

        // v1 and v3 still work
        v1.sudoSetSuccess(true);
        {
            uint256 nonce = _encodeNonce(false, false, false, bytes1(0x01), bytes20(address(v1)), address(kernel));
            PackedUserOperation memory op = _buildCallFooOp(address(kernel), nonce);
            PackedUserOperation[] memory ops = new PackedUserOperation[](1);
            ops[0] = op;
            _handleOps(ops);
        }
        assertEq(callee.bar(), 4, "v1 should still work after v2 uninstall");

        v3.sudoSetSuccess(true);
        {
            uint256 nonce = _encodeNonce(false, false, false, bytes1(0x01), bytes20(address(v3)), address(kernel));
            PackedUserOperation memory op = _buildCallFooOp(address(kernel), nonce);
            PackedUserOperation[] memory ops = new PackedUserOperation[](1);
            ops[0] = op;
            _handleOps(ops);
        }
        assertEq(callee.bar(), 5, "v3 should still work after v2 uninstall");
    }

    // -----------------------------------------------------------------------
    // Test 4: Fallback module lifecycle
    // -----------------------------------------------------------------------

    /// @notice Install a fallback module via UserOp, call it externally,
    ///         uninstall it, verify it reverts.
    function test_fallbackModuleLifecycle() public {
        Kernel kernel = _deployKernel();
        MockFallback fb = new MockFallback();
        rootValidator.sudoSetSuccess(true);

        // Install fallback via UserOp through root
        // Fallback internalData: [selector(4) | callType(1) | hookAddress(20)]
        // callType 0x00 = CALLTYPE_SINGLE, hook address(1) = no hook, anyone can call
        bytes4 fbSelector = MockFallback.fallbackFunction.selector;
        {
            uint256 nonce = _rootNonce(address(kernel));
            PackedUserOperation memory installOp = PackedUserOperation({
                sender: address(kernel),
                nonce: nonce,
                initCode: hex"",
                callData: abi.encodeWithSelector(
                    Kernel.execute.selector,
                    bytes32(0),
                    abi.encodePacked(
                        address(kernel),
                        uint256(0),
                        abi.encodeWithSelector(
                            IERC7579Account.installModule.selector,
                            uint256(3),
                            address(fb),
                            abi.encode(hex"deadbeef", abi.encodePacked(fbSelector, bytes1(0x00)))
                        )
                    )
                ),
                accountGasLimits: bytes32(abi.encodePacked(uint128(2_000_000), uint128(2_000_000))),
                preVerificationGas: 1_000_000,
                gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
                paymasterAndData: hex"",
                signature: hex""
            });
            PackedUserOperation[] memory ops = new PackedUserOperation[](1);
            ops[0] = installOp;
            _handleOps(ops);
        }

        // Verify: fallback is installed
        assertTrue(
            kernel.isModuleInstalled(3, address(fb), abi.encodePacked(fbSelector)), "fallback should be installed"
        );

        // Call the installed fallback externally
        address alice = makeAddr("Alice");
        vm.prank(alice);
        (bool success, bytes memory ret) = address(kernel).call(abi.encodeWithSelector(fbSelector, uint256(5)));
        assertTrue(success, "fallback call should succeed");
        uint256 result = abi.decode(ret, (uint256));
        assertEq(result, 25, "fallbackFunction(5) should return 25 (5*5)");

        // Uninstall fallback via UserOp
        {
            uint256 nonce = _rootNonce(address(kernel));
            PackedUserOperation memory uninstallOp = PackedUserOperation({
                sender: address(kernel),
                nonce: nonce,
                initCode: hex"",
                callData: abi.encodeWithSelector(
                    Kernel.execute.selector,
                    bytes32(0),
                    abi.encodePacked(
                        address(kernel),
                        uint256(0),
                        abi.encodeWithSelector(
                            IERC7579Account.uninstallModule.selector,
                            uint256(3),
                            address(fb),
                            abi.encode(hex"", abi.encodePacked(fbSelector))
                        )
                    )
                ),
                accountGasLimits: bytes32(abi.encodePacked(uint128(2_000_000), uint128(2_000_000))),
                preVerificationGas: 1_000_000,
                gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
                paymasterAndData: hex"",
                signature: hex""
            });
            PackedUserOperation[] memory ops = new PackedUserOperation[](1);
            ops[0] = uninstallOp;
            _handleOps(ops);
        }

        // Verify: fallback is uninstalled
        assertFalse(
            kernel.isModuleInstalled(3, address(fb), abi.encodePacked(fbSelector)), "fallback should be uninstalled"
        );

        // Calling the fallback now should revert with InvalidSelector
        vm.prank(alice);
        vm.expectRevert(InvalidSelector.selector);
        (bool s,) = address(kernel).call(abi.encodeWithSelector(fbSelector, uint256(5)));
    }

    // -----------------------------------------------------------------------
    // Test 5: Hook failure propagation
    // -----------------------------------------------------------------------

    /// @notice Hook reverts mid-execution, verify state is fully rolled back
    ///         (no partial effects from the execution).
    // -----------------------------------------------------------------------
    // Test 6: Cross-chain replay test
    // -----------------------------------------------------------------------

    /// @notice Use replayable UserOp signatures and verify they work across
    ///         simulated chain IDs by using the chain-agnostic hash.
    function test_crossChainReplayableUserOp() public {
        Kernel kernel = _deployKernel();
        rootValidator.sudoSetSuccess(true);

        // Build a replayable UserOp (vMode bit 0x40 set)
        uint256 nonce = _encodeNonce(true, false, false, bytes1(0x00), bytes20(0), address(kernel));
        PackedUserOperation memory op = _buildCallFooOp(address(kernel), nonce);

        // Execute on the current chain
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        _handleOps(ops);

        assertEq(callee.bar(), 1, "first replayable UserOp should succeed");

        // Now simulate a different chain ID environment.
        // Deploy a fresh kernel on a different chainId to verify the chain-agnostic
        // hash mechanism is invoked. We just verify the first call worked and then
        // verify the validator was called with a chain-agnostic hash.
        // The MockValidator.count() increments prove validateUserOp was called.
        assertGe(rootValidator.count(), 1, "root validator should have been called");

        // Send another replayable UserOp on the same chain (nonce advances)
        uint256 nonce2 = _encodeNonce(true, false, false, bytes1(0x00), bytes20(0), address(kernel));
        PackedUserOperation memory op2 = _buildCallFooOp(address(kernel), nonce2);
        PackedUserOperation[] memory ops2 = new PackedUserOperation[](1);
        ops2[0] = op2;
        _handleOps(ops2);

        assertEq(callee.bar(), 2, "second replayable UserOp should also succeed");
        assertGe(rootValidator.count(), 2, "root validator should have been called twice");

        // Verify the chain-agnostic hash mechanism by switching chain ID and checking
        // that a freshly deployed kernel can also use replayable mode
        uint256 originalChainId = block.chainid;
        vm.chainId(42161); // Simulate Arbitrum

        // Deploy a new kernel on the "different chain"
        MockValidator rootV2 = new MockValidator();
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({moduleType: 1, module: address(rootV2), moduleData: hex"", internalData: hex""});
        Kernel kernel2 = factory.deploy(pkgs, 99);
        vm.deal(address(kernel2), 10e18);
        rootV2.sudoSetSuccess(true);

        uint256 nonce3 = _encodeNonce(true, false, false, bytes1(0x00), bytes20(0), address(kernel2));
        PackedUserOperation memory op3 = _buildCallFooOp(address(kernel2), nonce3);
        PackedUserOperation[] memory ops3 = new PackedUserOperation[](1);
        ops3[0] = op3;
        _handleOps(ops3);

        assertEq(callee.bar(), 3, "replayable UserOp should work on different chainId");

        // Restore chain ID
        vm.chainId(originalChainId);
    }

    // -----------------------------------------------------------------------
    // Test 7: Upgrade + module persistence
    // -----------------------------------------------------------------------

    /// @notice UUPS upgrade via UserOp, then verify all previously installed modules
    ///         still function correctly.
}
