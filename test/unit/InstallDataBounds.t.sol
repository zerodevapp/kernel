// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {Kernel} from "src/Kernel.sol";
import {Kernel7702} from "src/Kernel7702.sol";
import {MockExecutor} from "../mock/MockExecutor.sol";
import {InvalidDataLength} from "src/types/Error.sol";
import {MODULE_TYPE_EXECUTOR} from "src/types/Constants.sol";

/// @notice TOB-KERNEL-10 regression: `installModule`/`uninstallModule` decode `initData` as an
///         `InstallModuleDataFormat` via an assembly cast. The struct's dynamic-field head offsets
///         must be bound to the declared `initData` slice — otherwise heads can point past it into
///         appended calldata, so the bytes an authority approved differ from the bytes Kernel reads.
contract InstallDataBoundsTest is Test {
    bytes4 constant INSTALL_SEL = bytes4(keccak256("installModule(uint256,address,bytes)"));
    bytes4 constant UNINSTALL_SEL = bytes4(keccak256("uninstallModule(uint256,address,bytes)"));

    IEntryPoint ep;
    Kernel kernel;
    MockExecutor executor;

    function setUp() public {
        ep = EntryPointLib.deploy();
        Kernel7702 template = new Kernel7702(ep);
        address eoa = makeAddr("Owner");
        vm.etch(eoa, abi.encodePacked(bytes3(0xef0100), address(template)));
        kernel = Kernel(payable(eoa));
        executor = new MockExecutor();
    }

    /// @dev Builds `sel(moduleType, module, initData)` calldata where the declared initData is just
    ///      the two 32-byte struct heads, both pointing at offset 0x40 — i.e., PAST the declared
    ///      initData end, into the appended region.
    function _outOfBoundsCall(bytes4 sel) internal view returns (bytes memory) {
        bytes memory maliciousInitData = abi.encodePacked(uint256(0x40), uint256(0x40));
        bytes memory appended = abi.encodePacked(uint256(0)); // length word the heads resolve to
        return bytes.concat(
            abi.encodeWithSelector(sel, uint256(MODULE_TYPE_EXECUTOR), address(executor), maliciousInitData), appended
        );
    }

    function test_InstallModuleRejectsHeadsOutsideDeclaredInitData() external {
        vm.prank(address(ep));
        (bool ok, bytes memory ret) = address(kernel).call(_outOfBoundsCall(INSTALL_SEL));
        assertFalse(ok, "out-of-bounds initData must revert");
        assertEq(bytes4(ret), InvalidDataLength.selector, "must revert with InvalidDataLength");
        assertFalse(kernel.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(executor), ""));
    }

    function test_UninstallModuleRejectsHeadsOutsideDeclaredInitData() external {
        vm.prank(address(ep));
        kernel.installModule(MODULE_TYPE_EXECUTOR, address(executor), abi.encode(hex"", hex""));

        vm.prank(address(ep));
        (bool ok, bytes memory ret) = address(kernel).call(_outOfBoundsCall(UNINSTALL_SEL));
        assertFalse(ok, "out-of-bounds initData must revert");
        assertEq(bytes4(ret), InvalidDataLength.selector, "must revert with InvalidDataLength");
        assertTrue(kernel.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(executor), ""));
    }

    function test_InstallModuleRejectsTruncatedInitData() external {
        vm.prank(address(ep));
        vm.expectRevert(InvalidDataLength.selector);
        kernel.installModule(MODULE_TYPE_EXECUTOR, address(executor), hex"deadbeef");
    }

    /// @dev Positive control: canonical ABI encoding still installs and uninstalls.
    function test_WellFormedInitDataStillWorks() external {
        vm.startPrank(address(ep));
        kernel.installModule(MODULE_TYPE_EXECUTOR, address(executor), abi.encode(hex"", hex""));
        assertTrue(kernel.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(executor), ""));
        kernel.uninstallModule(MODULE_TYPE_EXECUTOR, address(executor), abi.encode(hex"", hex""));
        assertFalse(kernel.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(executor), ""));
        vm.stopPrank();
    }
}
