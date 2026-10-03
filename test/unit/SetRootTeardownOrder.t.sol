// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {Kernel} from "src/Kernel.sol";
import {Kernel7702} from "src/Kernel7702.sol";
import {Install, ValidationInfo} from "src/types/Structs.sol";
import {PermissionId, ValidationId} from "src/types/Types.sol";
import {MockValidator} from "../mock/MockValidator.sol";
import {MockSigner} from "../mock/MockSigner.sol";
import {IPolicy} from "src/interfaces/IERC7579Modules.sol";
import {MODULE_TYPE_VALIDATOR, MODULE_TYPE_POLICY, MODULE_TYPE_SIGNER} from "src/types/Constants.sol";
import {permissionToIdentifier} from "src/lib/Utils.sol";

/// @dev Policy that records what the account's validation state looked like from inside its own
///      onUninstall callback — the observation window TOB-KERNEL-2 exploits.
contract StateProbePolicy is IPolicy {
    Kernel public kernel;
    ValidationId public vId;
    bool public probed;
    bool public sawInstalled;
    uint256 public sawPolicies;

    function arm(Kernel _kernel, ValidationId _vId) external {
        kernel = _kernel;
        vId = _vId;
    }

    function onInstall(bytes calldata) external payable override {}

    function onUninstall(bytes calldata) external payable override {
        probed = true;
        ValidationInfo memory info = kernel.validationInfo(vId);
        sawInstalled = info.installed;
        sawPolicies = info.policies.length;
    }

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_POLICY;
    }

    function isInitialized(address) external pure override returns (bool) {
        return false;
    }

    function checkUserOpPolicy(bytes32, PackedUserOperation calldata) external payable override returns (uint256) {
        return 0;
    }

    function checkSignaturePolicy(bytes32, address, bytes32, bytes calldata) external view override returns (uint256) {
        return 0;
    }
}

/// @notice TOB-KERNEL-2 residual regression: during setRoot(removeCurrent=true) teardown of a
///         permission root, every authorization revocation must land BEFORE any module callback
///         runs. Otherwise a policy's onUninstall observes the permission still installed with
///         fewer (or zero) policies and can reenter with signer-only authorization.
contract SetRootTeardownOrderTest is Test {
    IEntryPoint ep;
    Kernel kernel;
    StateProbePolicy probePolicy;
    MockSigner signer;
    MockValidator newRootValidator;

    PermissionId constant PERM = PermissionId.wrap(bytes4(0xdeadbeef));

    function setUp() public {
        ep = EntryPointLib.deploy();
        Kernel7702 template = new Kernel7702(ep);
        address eoa = makeAddr("Owner");
        vm.etch(eoa, abi.encodePacked(bytes3(0xef0100), address(template)));
        kernel = Kernel(payable(eoa));

        probePolicy = new StateProbePolicy();
        signer = new MockSigner();
        newRootValidator = new MockValidator();
        newRootValidator.sudoSetSuccess(true);

        Install[] memory packages = new Install[](2);
        packages[0] = Install({
            moduleType: MODULE_TYPE_POLICY,
            module: address(probePolicy),
            moduleData: hex"",
            internalData: abi.encodePacked(PERM)
        });
        packages[1] = Install({
            moduleType: MODULE_TYPE_SIGNER,
            module: address(signer),
            moduleData: hex"",
            internalData: abi.encodePacked(PERM)
        });
        vm.prank(address(ep));
        kernel.setRoot(packages, false, hex"");

        probePolicy.arm(kernel, permissionToIdentifier(PERM));
    }

    function test_PolicyCallbackObservesFullyRevokedPermission() external {
        Install[] memory newRoot = new Install[](1);
        newRoot[0] = Install({
            moduleType: MODULE_TYPE_VALIDATOR, module: address(newRootValidator), moduleData: hex"", internalData: hex""
        });

        bytes[] memory uninstallDataArr = new bytes[](2);
        uninstallDataArr[0] = hex""; // policy
        uninstallDataArr[1] = hex""; // signer

        vm.prank(address(ep));
        kernel.setRoot(newRoot, true, abi.encode(uninstallDataArr));

        assertTrue(probePolicy.probed(), "policy onUninstall should have run");
        assertFalse(probePolicy.sawInstalled(), "permission must already be revoked during policy callback");
        assertEq(probePolicy.sawPolicies(), 0, "policy state must already be cleared during policy callback");

        // Teardown completed: old permission gone, new root active.
        assertFalse(kernel.validationInfo(permissionToIdentifier(PERM)).installed, "old root must be uninstalled");
        assertTrue(kernel.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(newRootValidator), ""));
    }
}
