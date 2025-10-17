pragma solidity ^0.8.0;

import {Install, ValidationInfo} from "src/types/Structs.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {ValidationId, PermissionId} from "src/types/Types.sol";
import {MockPolicy} from "./mock/MockPolicy.sol";
import {MockSigner} from "./mock/MockSigner.sol";
import {MockCallee} from "./mock/MockCallee.sol";
import {KernelTestBase} from "./KernelTestBase.sol";
import {InvalidNonce, NotInstalled} from "src/types/Error.sol";
import {
    VALIDATION_TYPE_ROOT,
    VALIDATION_TYPE_VALIDATOR,
    VALIDATION_TYPE_PERMISSION,
    ERC1271_MAGICVALUE
} from "src/types/Constants.sol";
import {permissionToIdentifier} from "src/lib/Utils.sol";

import {console} from "forge-std/console.sol";

abstract contract KernelValidatorTest is KernelTestBase {
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
        if (useHook) {
            assertEq(hook.preHookData(address(kernel)), hex"");
        }
        if (!success) {
            vm.expectRevert();
        }
        ep.handleOps(ops, beneficiary);
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
            vm.expectRevert();
        }
        ep.handleOps(ops, beneficiary);
        if (useHook && success) {
            assertTrue(hook.preHookData(address(kernel)).length != 0);
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

        kernel.setRoot(ValidationId.wrap(bytes20(address(newValidator))));
    }

    function test_install_validator() external unitTest {
        assertTrue(kernel.supportsModule(1));
        ValidationId vId = ValidationId.wrap(bytes20(address(newValidator)));
        kernel.installModule(1, address(newValidator), abi.encode(hex"deadbeef", hex""));
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.hook == address(0));
        bytes4 ret = kernel.isValidSignature(
            keccak256("Hello world"),
            abi.encodePacked(bytes1(0x01), newValidator, _validatorSignHash(keccak256("Hello world"), true))
        );
        assertEq(ret, ERC1271_MAGICVALUE);
        assertTrue(kernel.isModuleInstalled(1, address(newValidator), hex""));
    }

    function test_install_validator_with_selector() external unitTest {
        assertTrue(kernel.supportsModule(1));
        ValidationId vId = ValidationId.wrap(bytes20(address(newValidator)));
        kernel.installModule(
            1, address(newValidator), abi.encode(hex"deadbeef", abi.encodePacked(address(0), kernel.execute.selector))
        );
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.hook == address(0));
        bytes4 ret = kernel.isValidSignature(
            keccak256("Hello world"),
            abi.encodePacked(bytes1(0x01), newValidator, _validatorSignHash(keccak256("Hello world"), true))
        );
        assertEq(ret, ERC1271_MAGICVALUE);
        assertTrue(kernel.isModuleInstalled(1, address(newValidator), hex""));

        _sendUserOpValidator(true, false);
    }

    function test_install_validator_with_other_selector() external unitTest {
        assertTrue(kernel.supportsModule(1));
        ValidationId vId = ValidationId.wrap(bytes20(address(newValidator)));
        kernel.installModule(
            1, address(newValidator), abi.encode(hex"deadbeef", abi.encodePacked(address(0), kernel.setNonce.selector))
        );
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.hook == address(0));
        bytes4 ret = kernel.isValidSignature(
            keccak256("Hello world"),
            abi.encodePacked(bytes1(0x01), newValidator, _validatorSignHash(keccak256("Hello world"), true))
        );
        assertEq(ret, ERC1271_MAGICVALUE);
        assertTrue(kernel.isModuleInstalled(1, address(newValidator), hex""));

        _sendUserOpValidator(false, false);
    }

    function test_install_validator_with_hook() external unitTest {
        assertTrue(kernel.supportsModule(4));
        kernel.installModule(4, address(hook), abi.encode(hex"", ""));
        assertTrue(kernel.supportsModule(1));
        ValidationId vId = ValidationId.wrap(bytes20(address(newValidator)));
        kernel.installModule(
            1,
            address(newValidator),
            abi.encode(hex"deadbeef", abi.encodePacked(address(hook), kernel.execute.selector))
        );
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.hook == address(0));
        bytes4 ret = kernel.isValidSignature(
            keccak256("Hello world"),
            abi.encodePacked(bytes1(0x01), newValidator, _validatorSignHash(keccak256("Hello world"), true))
        );
        assertEq(ret, ERC1271_MAGICVALUE);
        assertTrue(kernel.isModuleInstalled(1, address(newValidator), hex""));

        _sendUserOpValidator(true, true);
    }

    function test_install_validator_with_hook_notinstalled() external unitTest {
        assertTrue(kernel.supportsModule(4));
        assertTrue(kernel.supportsModule(1));
        ValidationId vId = ValidationId.wrap(bytes20(address(newValidator)));
        vm.expectRevert(NotInstalled.selector);
        kernel.installModule(
            1,
            address(newValidator),
            abi.encode(hex"deadbeef", abi.encodePacked(address(hook), kernel.execute.selector))
        );
    }

    function test_uninstall_validator() external unitTest {
        ValidationId vId = ValidationId.wrap(bytes20(address(newValidator)));
        kernel.installModule(1, address(newValidator), abi.encode(hex"deadbeef", hex""));
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.hook == address(0));
        kernel.uninstallModule(1, address(newValidator), abi.encode(hex"deadbeef", hex""));
        vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.hook == address(0));
    }

    /// forge-config: default.isolate = true
    function test_install_permission() external unitTest {
        assertTrue(kernel.supportsModule(5));
        assertTrue(kernel.supportsModule(6));
        ValidationId vId = permissionToIdentifier(permissionId);
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.hook == address(0));
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
        assertTrue(kernel.supportsModule(4));
        kernel.installModule(4, address(hook), abi.encode(hex"", ""));
        assertTrue(kernel.supportsModule(5));
        assertTrue(kernel.supportsModule(6));
        ValidationId vId = permissionToIdentifier(permissionId);
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.hook == address(0));
        assertFalse(kernel.isModuleInstalled(5, address(policy), abi.encodePacked(permissionId)));
        assertFalse(kernel.isModuleInstalled(6, address(signer), abi.encodePacked(permissionId)));
        Install[] memory pkgs = new Install[](2);
        pkgs[0] = Install({
            moduleType: 5,
            module: address(policy),
            moduleData: hex"deadbeef",
            internalData: abi.encodePacked(permissionId, hook, kernel.execute.selector)
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

        _sendUserOpPermission(true, true);
    }

    /// forge-config: default.isolate = true
    function test_install_permission_with_hook_notinstalled() external unitTest {
        assertTrue(kernel.supportsModule(4));
        assertTrue(kernel.supportsModule(5));
        assertTrue(kernel.supportsModule(6));
        ValidationId vId = permissionToIdentifier(permissionId);
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.hook == address(0));
        assertFalse(kernel.isModuleInstalled(5, address(policy), abi.encodePacked(permissionId)));
        assertFalse(kernel.isModuleInstalled(6, address(signer), abi.encodePacked(permissionId)));
        vm.expectRevert(NotInstalled.selector);
        Install[] memory pkgs = new Install[](2);
        pkgs[0] = Install({
            moduleType: 5,
            module: address(policy),
            moduleData: hex"deadbeef",
            internalData: abi.encodePacked(permissionId, hook, kernel.execute.selector)
        });
        pkgs[1] = Install({
            moduleType: 6,
            module: address(signer),
            moduleData: hex"deadbeef",
            internalData: abi.encodePacked(permissionId)
        });
        kernel.installModule(pkgs);
    }

    function test_install_policy() external unitTest {
        assertTrue(kernel.supportsModule(5));
        MockPolicy mock = new MockPolicy();
        ValidationId vId = permissionToIdentifier(permissionId);
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.hook == address(0));
        kernel.installModule(5, address(mock), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.hook == address(1));
        assertTrue(kernel.isModuleInstalled(5, address(mock), abi.encodePacked(permissionId)));
    }

    function test_uninstall_policy() external unitTest {
        MockPolicy mock = new MockPolicy();
        ValidationId vId = permissionToIdentifier(permissionId);
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.hook == address(0));
        kernel.installModule(5, address(mock), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.hook == address(1));
        kernel.uninstallModule(5, address(mock), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.hook == address(0));
    }

    function test_install_signer() external unitTest {
        assertTrue(kernel.supportsModule(6));
        MockSigner mock = new MockSigner();
        ValidationId vId = permissionToIdentifier(permissionId);
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.hook == address(0));
        kernel.installModule(6, address(mock), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.hook == address(1));
        assertTrue(kernel.isModuleInstalled(6, address(mock), abi.encodePacked(permissionId)));
    }

    function test_install_policy_existing_permission() external unitTest {
        Install[] memory pkgs = new Install[](2);
        pkgs[0] = Install({
            moduleType: 5,
            module: address(policy),
            moduleData: hex"deadbeef",
            internalData: abi.encodePacked(permissionId, address(0), kernel.execute.selector)
        });
        pkgs[1] = Install({
            moduleType: 6,
            module: address(signer),
            moduleData: hex"deadbeef",
            internalData: abi.encodePacked(permissionId)
        });
        kernel.installModule(pkgs);
        MockPolicy mock = new MockPolicy();
        ValidationId vId = permissionToIdentifier(permissionId);
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.hook == address(1));
        assertEq(vInfo.policies.length, 1);
        assertEq(vInfo.policies[0], address(policy));
        kernel.installModule(5, address(mock), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.hook == address(1));
        assertEq(vInfo.policies.length, 2);
        assertEq(vInfo.policies[0], address(policy));
        assertEq(vInfo.policies[1], address(mock));
        assertTrue(kernel.isModuleInstalled(5, address(mock), abi.encodePacked(permissionId)));
    }

    function test_uninstall_signer() external unitTest {
        MockSigner mock = new MockSigner();
        ValidationId vId = permissionToIdentifier(permissionId);
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.hook == address(0));
        kernel.installModule(6, address(mock), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.hook == address(1));
        assertTrue(vInfo.signer == address(mock));
        kernel.uninstallModule(6, address(mock), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.hook == address(0));
        assertTrue(vInfo.signer == address(0));
    }
}
