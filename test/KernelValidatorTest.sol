pragma solidity ^0.8.0;

import {Install, ValidationInfo} from "src/types/Structs.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {ValidationId, PermissionId} from "src/types/Types.sol";
import {MockPolicy} from "./mock/MockPolicy.sol";
import {MockSigner} from "./mock/MockSigner.sol";
import {MockCallee} from "./mock/MockCallee.sol";
import {MockValidator} from "./mock/MockValidator.sol";
import {KernelTestBase} from "./KernelTestBase.sol";
import {
    InvalidRootValidation,
    InvalidNonce,
    UnauthorizedCallData,
    InvalidPermissionUninstallOrder,
    ScopedExecutionHookStillInstalled,
    ScopedExecutionHookAlreadyInstalled,
    InvalidScopedExecutionHookTarget,
    InvalidDataLength,
    InvalidPermissionId,
    OccupiedValidationId,
    NotImplemented
} from "src/types/Error.sol";
import {ERC1271_MAGICVALUE, SCOPED_EXECUTION_HOOK_VALIDATION_SCOPE} from "src/types/Constants.sol";
import {
    permissionToIdentifier,
    validatorToIdentifier,
    validationScopedExecutionHookId,
    getScopedExecutionHookScope,
    getScopedExecutionHookValidationId
} from "src/lib/Utils.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {IModule} from "src/interfaces/IERC7579Modules.sol";

abstract contract KernelValidatorTest is KernelTestBase {
    function _validationScopedExecutionHookContext(ValidationId vId) internal pure returns (bytes memory) {
        return abi.encodePacked(SCOPED_EXECUTION_HOOK_VALIDATION_SCOPE, ValidationId.unwrap(vId));
    }

    function caller() external view returns (address) {
        return msg.sender;
    }

    function _sendUserOpValidator(bool success, bool useHook) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, false, false, bytes1(0x01), bytes20(address(newValidator))),
            initCode: hex"",
            callData: useHook
                ? abi.encodePacked(
                    kernel.executeUserOp.selector,
                    abi.encodeWithSelector(
                        kernel.execute.selector,
                        bytes32(0),
                        abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
                    )
                )
                : abi.encodeWithSelector(
                    kernel.execute.selector,
                    bytes32(0),
                    abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
                ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        ops[0].signature = _validatorSignUserOp(ops[0], true, false);
        address prevCaller = this.caller();
        vm.startPrank(beneficiary, beneficiary);
        if (useHook) {
            assertEq(hook.preHookData(address(kernel)), hex"");
        }
        if (!success) {
            vm.expectRevert(
                abi.encodeWithSelector(
                    IEntryPoint.FailedOpWithRevert.selector,
                    0,
                    "AA23 reverted",
                    abi.encodeWithSelector(UnauthorizedCallData.selector)
                )
            );
        }
        ep.handleOps(ops, beneficiary);
        vm.startPrank(prevCaller);
        if (useHook && success) {
            assertTrue(hook.preHookData(address(kernel)).length != 0);
        }
    }

    function _sendUserOpPermission(bool success, bool useHook) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, false, false, bytes1(0x02), PermissionId.unwrap(permissionId)),
            initCode: hex"",
            callData: useHook
                ? abi.encodePacked(
                    kernel.executeUserOp.selector,
                    abi.encodeWithSelector(
                        kernel.execute.selector,
                        bytes32(0),
                        abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
                    )
                )
                : abi.encodeWithSelector(
                    kernel.execute.selector,
                    bytes32(0),
                    abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
                ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        ops[0].signature = _permissionSignUserOp(ops[0], true, false);
        if (useHook) {
            assertEq(hook.preHookData(address(kernel)), hex"");
        }
        if (!success) {
            vm.expectRevert(
                abi.encodeWithSelector(
                    IEntryPoint.FailedOpWithRevert.selector,
                    0,
                    "AA23 reverted",
                    abi.encodeWithSelector(UnauthorizedCallData.selector)
                )
            );
        }
        vm.startPrank(beneficiary, beneficiary);
        ep.handleOps(ops, beneficiary);
        vm.stopPrank();
        if (useHook && success) {
            assertTrue(hook.preHookData(address(kernel)).length != 0);
            ValidationId vId = permissionToIdentifier(permissionId);
            bytes32 expectedId = validationScopedExecutionHookId(vId);
            assertEq(getScopedExecutionHookScope(expectedId), SCOPED_EXECUTION_HOOK_VALIDATION_SCOPE);
            assertEq(ValidationId.unwrap(getScopedExecutionHookValidationId(expectedId)), ValidationId.unwrap(vId));
            assertEq(hook.preCheckId(address(kernel)), expectedId);
            assertEq(hook.postCheckId(address(kernel)), expectedId);
        }
    }

    function test_set_valid_nonce() external unitTest {
        kernel.setValidNonceFrom(1);
        assertEq(kernel.validNonceFrom(), 1);

        Install[] memory packages = new Install[](3);
        packages[0] = Install({moduleType: 1, module: address(newValidator), internalData: hex"", moduleData: hex""});
        packages[1] = Install({
            moduleType: 5, module: address(policy), internalData: abi.encodePacked(permissionId), moduleData: hex""
        });
        packages[2] = Install({
            moduleType: 6, module: address(signer), internalData: abi.encodePacked(permissionId), moduleData: hex""
        });
        bytes memory sig = enableSig(0, true, false, packages, _rootSignHash);
        vm.expectRevert(InvalidNonce.selector);
        kernel.installModule(false, 0, packages, sig);
        sig = enableSig(uint256(1) << 64, true, false, packages, _rootSignHash);
        vm.expectRevert(InvalidNonce.selector);
        kernel.installModule(false, uint256(1) << 64, packages, sig);
        sig = enableSig(1, true, false, packages, _rootSignHash);
        kernel.installModule(false, 1, packages, sig);
    }

    function test_set_nonce() external unitTest {
        kernel.setNonce(0, 1);
        assertEq(kernel.nonce(0), 1);

        Install[] memory packages = new Install[](3);
        packages[0] = Install({moduleType: 1, module: address(newValidator), internalData: hex"", moduleData: hex""});
        packages[1] = Install({
            moduleType: 5, module: address(policy), internalData: abi.encodePacked(permissionId), moduleData: hex""
        });
        packages[2] = Install({
            moduleType: 6, module: address(signer), internalData: abi.encodePacked(permissionId), moduleData: hex""
        });
        bytes memory sig = enableSig(0, true, false, packages, _rootSignHash);
        vm.expectRevert(InvalidNonce.selector);
        kernel.installModule(false, 0, packages, sig);
        sig = enableSig(uint256(1) << 64, true, false, packages, _rootSignHash);
        kernel.installModule(false, uint256(1) << 64, packages, sig);
    }

    function test_set_valid_nonce_decrease_nonce() external unitTest {
        kernel.setValidNonceFrom(100);
        assertEq(kernel.validNonceFrom(), 100);
        assertEq(kernel.nonce(0), 100);
        vm.expectRevert(InvalidNonce.selector);
        kernel.setValidNonceFrom(1);
    }

    function test_change_root() external unitTest {
        Install[] memory packages = new Install[](3);
        packages[0] = Install({moduleType: 1, module: address(newValidator), internalData: hex"", moduleData: hex""});
        packages[1] = Install({
            moduleType: 5, module: address(policy), internalData: abi.encodePacked(permissionId), moduleData: hex""
        });
        packages[2] = Install({
            moduleType: 6, module: address(signer), internalData: abi.encodePacked(permissionId), moduleData: hex""
        });
        kernel.installModule(false, 0, packages, enableSig(0, true, false, packages, _rootSignHash));

        kernel.setRoot(validatorToIdentifier(newValidator));
        assertTrue(kernel.root() == validatorToIdentifier(newValidator));
    }

    function test_change_root_pkgs() external unitTest {
        Install[] memory packages = new Install[](3);
        packages[0] = Install({moduleType: 1, module: address(newValidator), internalData: hex"", moduleData: hex""});
        packages[1] = Install({
            moduleType: 5, module: address(policy), internalData: abi.encodePacked(permissionId), moduleData: hex""
        });
        packages[2] = Install({
            moduleType: 6, module: address(signer), internalData: abi.encodePacked(permissionId), moduleData: hex""
        });

        assertFalse(kernel.root() == validatorToIdentifier(newValidator));
        kernel.setRoot(packages, false, hex"");
        assertTrue(kernel.root() == validatorToIdentifier(newValidator));
    }

    function test_change_root_pkgs_remove_current() external unitTest {
        vm.skip(is7702 || isImmutable);
        Install[] memory packages = new Install[](3);
        packages[0] = Install({moduleType: 1, module: address(newValidator), internalData: hex"", moduleData: hex""});
        packages[1] = Install({
            moduleType: 5, module: address(policy), internalData: abi.encodePacked(permissionId), moduleData: hex""
        });
        packages[2] = Install({
            moduleType: 6, module: address(signer), internalData: abi.encodePacked(permissionId), moduleData: hex""
        });

        assertFalse(kernel.root() == validatorToIdentifier(newValidator));
        kernel.setRoot(packages, true, hex"");
        assertTrue(kernel.root() == validatorToIdentifier(newValidator));
    }

    function test_change_root_pkgs_current_permission() external unitTest {
        MockPolicy mockPolicy1 = new MockPolicy();
        MockPolicy mockPolicy2 = new MockPolicy();
        MockPolicy mockPolicy3 = new MockPolicy();
        MockPolicy mockPolicy4 = new MockPolicy();

        Install[] memory packages = new Install[](3);
        packages[0] = Install({
            moduleType: 5, module: address(policy), internalData: abi.encodePacked(permissionId), moduleData: hex""
        });
        packages[1] = Install({
            moduleType: 5, module: address(mockPolicy1), internalData: abi.encodePacked(permissionId), moduleData: hex""
        });
        packages[2] = Install({
            moduleType: 6, module: address(signer), internalData: abi.encodePacked(permissionId), moduleData: hex""
        });

        assertFalse(kernel.root() == permissionToIdentifier(permissionId));
        kernel.setRoot(packages, false, hex"");
        assertTrue(kernel.root() == permissionToIdentifier(permissionId));
        kernel.installModule(
            11,
            address(hook),
            abi.encode(
                bytes("hook install"), _validationScopedExecutionHookContext(permissionToIdentifier(permissionId))
            )
        );

        packages[0] = Install({
            moduleType: 5, module: address(policy), internalData: abi.encodePacked(hex"efefefef"), moduleData: hex""
        });
        packages[1] = Install({
            moduleType: 5,
            module: address(mockPolicy1),
            internalData: abi.encodePacked(hex"efefefef"),
            moduleData: hex""
        });
        packages[2] = Install({
            moduleType: 6, module: address(signer), internalData: abi.encodePacked(hex"efefefef"), moduleData: hex""
        });

        bytes[] memory uninstallData = new bytes[](4);
        uninstallData[0] = hex"a1";
        uninstallData[1] = hex"a2";
        uninstallData[2] = hex"51";
        uninstallData[3] = hex"42";
        vm.expectCall(address(signer), abi.encodeWithSelector(IModule.onUninstall.selector, hex"51"));
        vm.expectCall(address(hook), abi.encodeWithSelector(IModule.onUninstall.selector, hex"42"));

        kernel.setRoot(packages, true, abi.encode(uninstallData));
        assertTrue(kernel.root() == permissionToIdentifier(PermissionId.wrap(bytes4(0xefefefef))));
    }

    function test_change_root_pkgs_remove_current_fail_7702_or_immutable() external unitTest {
        vm.skip(!is7702 && !isImmutable);
        Install[] memory packages = new Install[](3);
        packages[0] = Install({moduleType: 1, module: address(newValidator), internalData: hex"", moduleData: hex""});
        packages[1] = Install({
            moduleType: 5, module: address(policy), internalData: abi.encodePacked(permissionId), moduleData: hex""
        });
        packages[2] = Install({
            moduleType: 6, module: address(signer), internalData: abi.encodePacked(permissionId), moduleData: hex""
        });

        vm.expectRevert(InvalidRootValidation.selector);
        kernel.setRoot(packages, true, hex"");
    }

    function test_install_validator() external unitTest {
        assertTrue(kernel.supportsModule(1));
        ValidationId vId = ValidationId.wrap(bytes21(abi.encodePacked(bytes1(0x01), bytes20(address(newValidator)))));
        kernel.installModule(1, address(newValidator), abi.encode(hex"deadbeef", hex""));
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.installed);
        bytes4 ret = kernel.isValidSignature(
            keccak256("Hello world"),
            abi.encodePacked(bytes1(0x01), newValidator, _validatorSignHash(keccak256("Hello world"), true))
        );
        assertEq(ret, ERC1271_MAGICVALUE);
        assertTrue(kernel.isModuleInstalled(1, address(newValidator), hex""));
    }

    function test_install_validator_with_selector() external unitTest {
        assertTrue(kernel.supportsModule(1));
        ValidationId vId = ValidationId.wrap(bytes21(abi.encodePacked(bytes1(0x01), bytes20(address(newValidator)))));
        kernel.installModule(
            1, address(newValidator), abi.encode(hex"deadbeef", abi.encodePacked(kernel.execute.selector))
        );
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.installed);
        bytes4 ret = kernel.isValidSignature(
            keccak256("Hello world"),
            abi.encodePacked(bytes1(0x01), newValidator, _validatorSignHash(keccak256("Hello world"), true))
        );
        assertEq(ret, ERC1271_MAGICVALUE);
        assertTrue(kernel.isModuleInstalled(1, address(newValidator), hex""));

        _sendUserOpValidator(true, false);
    }

    function test_install_validator_with_selector_and_reinstall() external unitTest {
        assertTrue(kernel.supportsModule(1));
        ValidationId vId = ValidationId.wrap(bytes21(abi.encodePacked(bytes1(0x01), bytes20(address(newValidator)))));
        kernel.installModule(
            1, address(newValidator), abi.encode(hex"deadbeef", abi.encodePacked(kernel.execute.selector))
        );
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.installed);
        // Non-empty install bumps nonce once via _grantAccess.
        assertEq(vInfo.nonce, 1);
        bytes4 ret = kernel.isValidSignature(
            keccak256("Hello world"),
            abi.encodePacked(bytes1(0x01), newValidator, _validatorSignHash(keccak256("Hello world"), true))
        );
        assertEq(ret, ERC1271_MAGICVALUE);
        assertTrue(kernel.isModuleInstalled(1, address(newValidator), hex""));

        _sendUserOpValidator(true, false);

        kernel.uninstallModule(1, address(newValidator), abi.encode(hex"", hex""));
        vInfo = kernel.validationInfo(vId);
        // uninstall does not touch nonce; the bump on the next install invalidates
        // any stale `allowed[vId][sel]` entries from the prior incarnation.
        assertEq(vInfo.nonce, 1);
        kernel.installModule(
            1, address(newValidator), abi.encode(hex"deadbeef", abi.encodePacked(kernel.setNonce.selector))
        );
        vInfo = kernel.validationInfo(vId);
        // re-install with non-empty internalData bumps nonce once -> 2.
        assertEq(vInfo.nonce, 2);

        _sendUserOpValidator(false, false);

        kernel.grantAccess(vId, abi.encodePacked(kernel.execute.selector));

        _sendUserOpValidator(true, false);
    }

    function test_install_validator_with_other_selector() external unitTest {
        assertTrue(kernel.supportsModule(1));
        ValidationId vId = ValidationId.wrap(bytes21(abi.encodePacked(bytes1(0x01), bytes20(address(newValidator)))));
        kernel.installModule(
            1, address(newValidator), abi.encode(hex"deadbeef", abi.encodePacked(kernel.setNonce.selector))
        );
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.installed);
        bytes4 ret = kernel.isValidSignature(
            keccak256("Hello world"),
            abi.encodePacked(bytes1(0x01), newValidator, _validatorSignHash(keccak256("Hello world"), true))
        );
        assertEq(ret, ERC1271_MAGICVALUE);
        assertTrue(kernel.isModuleInstalled(1, address(newValidator), hex""));

        _sendUserOpValidator(false, false);
    }

    function test_uninstall_validator() external unitTest {
        ValidationId vId = ValidationId.wrap(bytes21(abi.encodePacked(bytes1(0x01), bytes20(address(newValidator)))));
        kernel.installModule(1, address(newValidator), abi.encode(hex"deadbeef", hex""));
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.installed);
        kernel.uninstallModule(1, address(newValidator), abi.encode(hex"deadbeef", hex""));
        vInfo = kernel.validationInfo(vId);
        assertTrue(!vInfo.installed);
    }

    /// forge-config: default.isolate = true
    function test_install_permission() external unitTest {
        assertTrue(kernel.supportsModule(5));
        assertTrue(kernel.supportsModule(6));
        ValidationId vId = permissionToIdentifier(permissionId);
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(!vInfo.installed);
        assertFalse(kernel.isModuleInstalled(5, address(policy), abi.encodePacked(permissionId)));
        assertFalse(kernel.isModuleInstalled(6, address(signer), abi.encodePacked(permissionId)));
        Install[] memory pkgs = new Install[](2);
        pkgs[0] = Install({
            moduleType: 5,
            module: address(policy),
            moduleData: hex"deadbeef",
            internalData: abi.encodePacked(permissionId)
        });
        pkgs[1] = Install({
            moduleType: 6,
            module: address(signer),
            moduleData: hex"deadbeef",
            internalData: abi.encodePacked(permissionId)
        });
        kernel.installModule(pkgs);
        bytes4 ret = kernel.isValidSignature(
            keccak256("Hello world"),
            abi.encodePacked(bytes1(0x02), permissionId, _permissionSignHash(keccak256("Hello world"), true))
        );
        assertEq(ret, ERC1271_MAGICVALUE);
        assertTrue(kernel.isModuleInstalled(5, address(policy), abi.encodePacked(permissionId)));
        assertTrue(kernel.isModuleInstalled(6, address(signer), abi.encodePacked(permissionId)));
    }

    /// forge-config: default.isolate = true
    function test_install_permission_with_hook() external unitTest {
        assertFalse(kernel.supportsModule(4));
        assertTrue(kernel.supportsModule(11));
        assertTrue(kernel.supportsModule(5));
        assertTrue(kernel.supportsModule(6));
        ValidationId vId = permissionToIdentifier(permissionId);
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertFalse(vInfo.installed);
        assertFalse(kernel.isModuleInstalled(5, address(policy), abi.encodePacked(permissionId)));
        assertFalse(kernel.isModuleInstalled(6, address(signer), abi.encodePacked(permissionId)));
        Install[] memory pkgs = new Install[](3);
        pkgs[0] = Install({
            moduleType: 5,
            module: address(policy),
            moduleData: hex"deadbeef",
            internalData: abi.encodePacked(permissionId)
        });
        pkgs[1] = Install({
            moduleType: 6,
            module: address(signer),
            moduleData: hex"deadbeef",
            internalData: abi.encodePacked(permissionId, kernel.execute.selector)
        });
        pkgs[2] = Install({
            moduleType: 11,
            module: address(hook),
            moduleData: hex"deadbeef",
            internalData: _validationScopedExecutionHookContext(vId)
        });
        kernel.installModule(pkgs);
        vInfo = kernel.validationInfo(vId);
        assertEq(address(vInfo.scopedExecutionHook), address(hook));
        assertTrue(kernel.isModuleInstalled(11, address(hook), _validationScopedExecutionHookContext(vId)));
        bytes4 ret = kernel.isValidSignature(
            keccak256("Hello world"),
            abi.encodePacked(bytes1(0x02), permissionId, _permissionSignHash(keccak256("Hello world"), true))
        );
        assertEq(ret, ERC1271_MAGICVALUE);
        assertTrue(kernel.isModuleInstalled(5, address(policy), abi.encodePacked(permissionId)));
        assertTrue(kernel.isModuleInstalled(6, address(signer), abi.encodePacked(permissionId)));

        _sendUserOpPermission(true, true);
    }

    /// forge-config: default.isolate = true

    function test_install_policy() external unitTest {
        assertTrue(kernel.supportsModule(5));
        MockPolicy mock = new MockPolicy();
        ValidationId vId = permissionToIdentifier(permissionId);
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(!vInfo.installed);
        kernel.installModule(5, address(mock), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        vInfo = kernel.validationInfo(vId);
        // it should return address(0) as signer is not installed properly
        assertTrue(!vInfo.installed);
        assertTrue(kernel.isModuleInstalled(5, address(mock), abi.encodePacked(permissionId)));
    }

    function test_uninstall_policy() external unitTest {
        MockPolicy mock = new MockPolicy();
        ValidationId vId = permissionToIdentifier(permissionId);
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(!vInfo.installed);
        kernel.installModule(5, address(mock), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        vInfo = kernel.validationInfo(vId);
        assertTrue(!vInfo.installed);
        kernel.uninstallModule(5, address(mock), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        vInfo = kernel.validationInfo(vId);
        assertTrue(!vInfo.installed);
    }

    function test_install_signer() external unitTest {
        assertTrue(kernel.supportsModule(6));
        MockSigner mock = new MockSigner();
        ValidationId vId = permissionToIdentifier(permissionId);
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(!vInfo.installed);
        kernel.installModule(6, address(mock), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.installed);
        assertTrue(kernel.isModuleInstalled(6, address(mock), abi.encodePacked(permissionId)));
    }

    function test_install_policy_existing_permission() external unitTest {
        Install[] memory pkgs = new Install[](2);
        pkgs[0] = Install({
            moduleType: 5,
            module: address(policy),
            moduleData: hex"deadbeef",
            internalData: abi.encodePacked(permissionId)
        });
        pkgs[1] = Install({
            moduleType: 6,
            module: address(signer),
            moduleData: hex"deadbeef",
            internalData: abi.encodePacked(permissionId, kernel.execute.selector)
        });
        kernel.installModule(pkgs);
        MockPolicy mock = new MockPolicy();
        ValidationId vId = permissionToIdentifier(permissionId);
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.installed);
        assertEq(vInfo.policies.length, 1);
        assertEq(vInfo.policies[0], address(policy));
        kernel.installModule(5, address(mock), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.installed);
        assertEq(vInfo.policies.length, 2);
        assertEq(vInfo.policies[0], address(policy));
        assertEq(vInfo.policies[1], address(mock));
        assertTrue(kernel.isModuleInstalled(5, address(mock), abi.encodePacked(permissionId)));
    }

    function test_uninstall_signer() external unitTest {
        MockSigner mock = new MockSigner();
        ValidationId vId = permissionToIdentifier(permissionId);
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(!vInfo.installed);
        kernel.installModule(6, address(mock), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.installed);
        assertTrue(vInfo.signer == address(mock));
        kernel.uninstallModule(6, address(mock), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        vInfo = kernel.validationInfo(vId);
        assertTrue(!vInfo.installed);
        assertTrue(vInfo.signer == address(0));
    }

    function test_execution_hook_requires_completed_permission() external unitTest {
        vm.expectRevert(InvalidScopedExecutionHookTarget.selector);
        kernel.installModule(
            11,
            address(hook),
            abi.encode(hex"deadbeef", _validationScopedExecutionHookContext(permissionToIdentifier(permissionId)))
        );
    }

    function test_execution_hook_permission_lifecycle_and_uninstall_order() external unitTest {
        ValidationId vId = permissionToIdentifier(permissionId);
        bytes memory hookContext = _validationScopedExecutionHookContext(vId);
        kernel.installModule(6, address(signer), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        kernel.installModule(11, address(hook), abi.encode(hex"deadbeef", hookContext));

        ValidationInfo memory info = kernel.validationInfo(vId);
        assertTrue(info.installed);
        assertEq(address(info.scopedExecutionHook), address(hook));
        assertTrue(kernel.isModuleInstalled(11, address(hook), hookContext));

        vm.expectRevert(ScopedExecutionHookAlreadyInstalled.selector);
        kernel.installModule(11, address(hook), abi.encode(hex"deadbeef", hookContext));

        vm.expectRevert(ScopedExecutionHookStillInstalled.selector);
        kernel.uninstallModule(6, address(signer), abi.encode(hex"", abi.encodePacked(permissionId)));

        kernel.uninstallModule(11, address(hook), abi.encode(hex"", hookContext));
        assertFalse(kernel.isModuleInstalled(11, address(hook), hookContext));
        assertEq(address(kernel.validationInfo(vId).scopedExecutionHook), address(0));

        kernel.uninstallModule(6, address(signer), abi.encode(hex"", abi.encodePacked(permissionId)));
        assertFalse(kernel.validationInfo(permissionToIdentifier(permissionId)).installed);
    }

    function test_validator_scoped_execution_hook() external unitTest {
        ValidationId vId = validatorToIdentifier(newValidator);
        kernel.installModule(
            1, address(newValidator), abi.encode(hex"deadbeef", abi.encodePacked(kernel.execute.selector))
        );
        bytes memory hookContext = _validationScopedExecutionHookContext(vId);
        kernel.installModule(11, address(hook), abi.encode(hex"deadbeef", hookContext));

        assertTrue(kernel.isModuleInstalled(11, address(hook), hookContext));
        assertEq(address(kernel.validationInfo(vId).scopedExecutionHook), address(hook));

        _sendUserOpValidator(true, true);
        bytes32 expectedId = validationScopedExecutionHookId(vId);
        assertEq(getScopedExecutionHookScope(expectedId), SCOPED_EXECUTION_HOOK_VALIDATION_SCOPE);
        assertEq(ValidationId.unwrap(getScopedExecutionHookValidationId(expectedId)), ValidationId.unwrap(vId));
        assertEq(hook.preCheckId(address(kernel)), expectedId);
        assertEq(hook.postCheckId(address(kernel)), expectedId);

        vm.expectRevert(ScopedExecutionHookStillInstalled.selector);
        kernel.uninstallModule(1, address(newValidator), abi.encode(hex"", hex""));

        kernel.uninstallModule(11, address(hook), abi.encode(hex"", hookContext));
        kernel.uninstallModule(1, address(newValidator), abi.encode(hex"", hex""));
        assertFalse(kernel.validationInfo(vId).installed);
    }

    function test_set_root_removes_validator_execution_hook_before_validator() external unitTest {
        ValidationId oldRoot = validatorToIdentifier(newValidator);
        kernel.installModule(
            1, address(newValidator), abi.encode(hex"deadbeef", abi.encodePacked(kernel.execute.selector))
        );
        kernel.installModule(
            11, address(hook), abi.encode(hex"deadbeef", _validationScopedExecutionHookContext(oldRoot))
        );
        kernel.setRoot(oldRoot);

        MockValidator replacement = new MockValidator();
        Install[] memory packages = new Install[](1);
        packages[0] = Install({
            moduleType: 1,
            module: address(replacement),
            moduleData: hex"deadbeef",
            internalData: abi.encodePacked(kernel.execute.selector)
        });
        bytes[] memory uninstallData = new bytes[](2);
        uninstallData[0] = hex"aaaa";
        uninstallData[1] = hex"bbbb";
        kernel.setRoot(packages, true, abi.encode(uninstallData));

        assertEq(ValidationId.unwrap(kernel.root()), ValidationId.unwrap(validatorToIdentifier(replacement)));
        assertFalse(kernel.validationInfo(oldRoot).installed);
        assertEq(address(kernel.validationInfo(oldRoot).scopedExecutionHook), address(0));
    }

    function test_execution_hook_rejects_invalid_scope_and_length() external unitTest {
        vm.expectRevert(InvalidScopedExecutionHookTarget.selector);
        kernel.installModule(11, address(hook), abi.encode(hex"", abi.encodePacked(bytes1(0xff), bytes4(0))));

        vm.expectRevert(InvalidDataLength.selector);
        kernel.installModule(
            11,
            address(hook),
            abi.encode(
                hex"", abi.encodePacked(SCOPED_EXECUTION_HOOK_VALIDATION_SCOPE, PermissionId.unwrap(permissionId))
            )
        );
    }

    function test_generic_hook_type_is_unsupported() external unitTest {
        assertFalse(kernel.supportsModule(4));
        vm.expectRevert(NotImplemented.selector);
        kernel.installModule(4, address(hook), abi.encode(hex"", hex""));
    }

    function test_uninstall_policy_not_last_reverts() external unitTest {
        MockPolicy policy2 = new MockPolicy();
        kernel.installModule(5, address(policy), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        kernel.installModule(5, address(policy2), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        kernel.installModule(6, address(signer), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        vm.expectRevert(InvalidPermissionUninstallOrder.selector);
        kernel.uninstallModule(5, address(policy), abi.encode(hex"", abi.encodePacked(permissionId)));
    }

    function test_uninstall_signer_with_policies_reverts() external unitTest {
        kernel.installModule(5, address(policy), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        kernel.installModule(6, address(signer), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        vm.expectRevert(InvalidPermissionUninstallOrder.selector);
        kernel.uninstallModule(6, address(signer), abi.encode(hex"", abi.encodePacked(permissionId)));
    }
}
