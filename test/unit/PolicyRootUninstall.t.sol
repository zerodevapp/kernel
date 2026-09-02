// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {Kernel} from "src/Kernel.sol";
import {Kernel7702} from "src/Kernel7702.sol";
import {Install} from "src/types/Structs.sol";
import {PermissionId, ValidationId} from "src/types/Types.sol";
import {MockPolicy} from "../mock/MockPolicy.sol";
import {MockSigner} from "../mock/MockSigner.sol";
import {CannotUninstallRoot} from "src/types/Error.sol";
import {MODULE_TYPE_POLICY, MODULE_TYPE_SIGNER} from "src/types/Constants.sol";
import {permissionToIdentifier} from "src/lib/Utils.sol";

/// @notice TOB-KERNEL-7 regression: the current root permission's policies must be protected by
///         the same CannotUninstallRoot invariant as validators and signers. Otherwise a non-root
///         authority limited to uninstallModule can strip the root's policy and leave the root
///         signer unconstrained.
contract PolicyRootUninstallTest is Test {
    IEntryPoint ep;
    Kernel kernel;
    MockPolicy policy;
    MockSigner signer;

    PermissionId constant ROOT_PERM = PermissionId.wrap(bytes4(0xdeadbeef));
    PermissionId constant OTHER_PERM = PermissionId.wrap(bytes4(0xbeefdead));

    function setUp() public {
        ep = EntryPointLib.deploy();
        Kernel7702 template = new Kernel7702(ep);
        address eoa = makeAddr("Owner");
        vm.etch(eoa, abi.encodePacked(bytes3(0xef0100), address(template)));
        kernel = Kernel(payable(eoa));

        policy = new MockPolicy();
        signer = new MockSigner();

        // Root = permission {policy, signer}.
        vm.prank(address(ep));
        kernel.setRoot(_permissionPackages(ROOT_PERM), false, hex"");

        // A second, non-root permission with the same modules.
        vm.prank(address(ep));
        kernel.installModule(_permissionPackages(OTHER_PERM));
    }

    function test_RootPermissionPolicyCannotBeUninstalled() external {
        vm.prank(address(ep));
        vm.expectRevert(CannotUninstallRoot.selector);
        kernel.uninstallModule(MODULE_TYPE_POLICY, address(policy), _uninstallData(ROOT_PERM));

        assertEq(
            kernel.validationInfo(permissionToIdentifier(ROOT_PERM)).policies.length,
            1,
            "root policy must remain installed"
        );
    }

    /// @dev Positive control: the same call on a non-root permission still works.
    function test_NonRootPermissionPolicyCanBeUninstalled() external {
        vm.prank(address(ep));
        kernel.uninstallModule(MODULE_TYPE_POLICY, address(policy), _uninstallData(OTHER_PERM));

        assertEq(
            kernel.validationInfo(permissionToIdentifier(OTHER_PERM)).policies.length,
            0,
            "non-root policy should be removed"
        );
    }

    function _permissionPackages(PermissionId permId) internal view returns (Install[] memory packages) {
        packages = new Install[](2);
        packages[0] = Install({
            moduleType: MODULE_TYPE_POLICY,
            module: address(policy),
            moduleData: hex"",
            internalData: abi.encodePacked(permId)
        });
        packages[1] = Install({
            moduleType: MODULE_TYPE_SIGNER,
            module: address(signer),
            moduleData: hex"",
            internalData: abi.encodePacked(permId)
        });
    }

    function _uninstallData(PermissionId permId) internal pure returns (bytes memory) {
        return abi.encode(bytes(""), abi.encodePacked(permId));
    }
}
