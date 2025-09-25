pragma solidity ^0.8.0;

import {Install, ValidationInfo} from "src/types/Structs.sol";
import {ValidationId} from "src/types/Types.sol";
import {MockPolicy} from "./mock/MockPolicy.sol";
import {MockSigner} from "./mock/MockSigner.sol";
import {KernelTestBase} from "./KernelTestBase.sol";
import {InvalidNonce} from "src/types/Error.sol";
import {
    VALIDATION_TYPE_ROOT,
    VALIDATION_TYPE_VALIDATOR,
    VALIDATION_TYPE_PERMISSION,
    ERC1271_MAGICVALUE
} from "src/types/Constants.sol";

abstract contract KernelValidatorTest is KernelTestBase {
    function test_set_valid_nonce() external unitTest {
        kernel.setValidNonceFrom(1);
        assertEq(kernel.validNonceFrom(), 1);

        Install[] memory packages = new Install[](2);
        packages[0] = Install({moduleType: 1, module: address(newValidator), internalData: hex"", moduleData: hex""});
        packages[1] = Install({
            moduleType: 5,
            module: address(policy),
            internalData: abi.encodePacked(permissionId),
            moduleData: hex""
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

        Install[] memory packages = new Install[](2);
        packages[0] = Install({moduleType: 1, module: address(newValidator), internalData: hex"", moduleData: hex""});
        packages[1] = Install({
            moduleType: 5,
            module: address(policy),
            internalData: abi.encodePacked(permissionId),
            moduleData: hex""
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
        Install[] memory packages = new Install[](2);
        packages[0] = Install({moduleType: 1, module: address(newValidator), internalData: hex"", moduleData: hex""});
        packages[1] = Install({
            moduleType: 5,
            module: address(policy),
            internalData: abi.encodePacked(permissionId),
            moduleData: hex""
        });
        kernel.installModule(false, 0, packages, enableSig(0, true, false, packages, _rootSignHash));

        kernel.setRoot(ValidationId.wrap(bytes20(address(newValidator))));
    }

    function test_install_validator() external unitTest {
        assertTrue(kernel.supportsModule(1));
        ValidationId vId = ValidationId.wrap(bytes20(address(newValidator)));
        kernel.installModule(1, address(newValidator), abi.encode(hex"deadbeef", hex""));
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.vType == VALIDATION_TYPE_VALIDATOR);
        bytes4 ret = kernel.isValidSignature(
            keccak256("Hello world"), abi.encodePacked(newValidator, _validatorSignHash(keccak256("Hello world"), true))
        );
        assertEq(ret, ERC1271_MAGICVALUE);
        assertTrue(kernel.isModuleInstalled(1, address(newValidator), hex""));
    }

    function test_uninstall_validator() external unitTest {
        ValidationId vId = ValidationId.wrap(bytes20(address(newValidator)));
        kernel.installModule(1, address(newValidator), abi.encode(hex"deadbeef", hex""));
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.vType == VALIDATION_TYPE_VALIDATOR);
        kernel.uninstallModule(1, address(newValidator), abi.encode(hex"deadbeef", hex""));
        vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.vType == VALIDATION_TYPE_ROOT);
    }

    function test_install_permission() external unitTest {
        assertTrue(kernel.supportsModule(5));
        assertTrue(kernel.supportsModule(6));
        ValidationId vId = ValidationId.wrap(permissionId);
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.vType == VALIDATION_TYPE_ROOT);
        assertFalse(kernel.isModuleInstalled(5, address(policy), abi.encodePacked(permissionId)));
        assertFalse(kernel.isModuleInstalled(6, address(signer), abi.encodePacked(permissionId)));
        kernel.installModule(5, address(policy), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        kernel.installModule(6, address(signer), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        bytes4 ret = kernel.isValidSignature(
            keccak256("Hello world"),
            abi.encodePacked(permissionId, _permissionSignHash(keccak256("Hello world"), true))
        );
        assertEq(ret, ERC1271_MAGICVALUE);
        assertTrue(kernel.isModuleInstalled(5, address(policy), abi.encodePacked(permissionId)));
        assertTrue(kernel.isModuleInstalled(6, address(signer), abi.encodePacked(permissionId)));
    }

    function test_install_policy() external unitTest {
        assertTrue(kernel.supportsModule(5));
        MockPolicy mock = new MockPolicy();
        ValidationId vId = ValidationId.wrap(permissionId);
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.vType == VALIDATION_TYPE_ROOT);
        kernel.installModule(5, address(mock), abi.encode(hex"deadbeef", abi.encodePacked(vId)));
        vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.vType == VALIDATION_TYPE_PERMISSION);
        assertTrue(kernel.isModuleInstalled(5, address(mock), abi.encodePacked(permissionId)));
    }

    function test_uninstall_policy() external unitTest {
        MockPolicy mock = new MockPolicy();
        ValidationId vId = ValidationId.wrap(permissionId);
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.vType == VALIDATION_TYPE_ROOT);
        kernel.installModule(5, address(mock), abi.encode(hex"deadbeef", abi.encodePacked(vId)));
        vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.vType == VALIDATION_TYPE_PERMISSION);
        kernel.uninstallModule(5, address(mock), abi.encode(hex"deadbeef", abi.encodePacked(vId)));
        vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.vType == VALIDATION_TYPE_ROOT);
    }

    function test_install_signer() external unitTest {
        assertTrue(kernel.supportsModule(6));
        MockSigner mock = new MockSigner();
        ValidationId vId = ValidationId.wrap(permissionId);
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.vType == VALIDATION_TYPE_ROOT);
        kernel.installModule(6, address(mock), abi.encode(hex"deadbeef", abi.encodePacked(vId)));
        vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.vType == VALIDATION_TYPE_PERMISSION);
        assertTrue(kernel.isModuleInstalled(6, address(mock), abi.encodePacked(permissionId)));
    }

    function test_uninstall_signer() external unitTest {
        MockSigner mock = new MockSigner();
        ValidationId vId = ValidationId.wrap(bytes20(keccak256(abi.encodePacked("deadbeef"))));
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.vType == VALIDATION_TYPE_ROOT);
        kernel.installModule(6, address(mock), abi.encode(hex"deadbeef", abi.encodePacked(vId)));
        vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.vType == VALIDATION_TYPE_PERMISSION);
        assertTrue(vInfo.signer == address(mock));
        kernel.uninstallModule(6, address(mock), abi.encode(hex"deadbeef", abi.encodePacked(vId)));
        vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.vType == VALIDATION_TYPE_ROOT);
        assertTrue(vInfo.signer == address(0));
    }
}
