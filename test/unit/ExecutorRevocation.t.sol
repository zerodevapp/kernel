// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {Kernel} from "src/Kernel.sol";
import {Kernel7702} from "src/Kernel7702.sol";
import {MockReentrantExecutor} from "../mock/MockReentrantExecutor.sol";
import {MODULE_TYPE_EXECUTOR} from "src/types/Constants.sol";

/// @notice Module authority must be revoked before the module's onUninstall callback runs.
/// @dev `executeFromExecutor` gates on `ExecutorConfig.installed` and nothing else, so an executor
///      called back while still flagged installed can spend the account during its own revocation.
contract ExecutorRevocationTest is Test {
    IEntryPoint ep;
    Kernel kernel;
    MockReentrantExecutor executor;
    address attacker;

    function setUp() public {
        ep = EntryPointLib.deploy();
        Kernel7702 template = new Kernel7702(ep);

        address eoa = makeAddr("Owner");
        vm.etch(eoa, abi.encodePacked(bytes3(0xef0100), address(template)));
        kernel = Kernel(payable(eoa));
        vm.deal(eoa, 10 ether);

        attacker = makeAddr("Attacker");
        executor = new MockReentrantExecutor();
        executor.setReentryCall(attacker, 1 ether);

        vm.prank(address(ep));
        kernel.installModule(MODULE_TYPE_EXECUTOR, address(executor), abi.encode(hex"", hex""));
    }

    /// @dev Positive control: the same call the reentrancy test expects to fail must succeed while
    ///      the executor is installed, otherwise that test would pass for the wrong reason.
    function test_InstalledExecutorCanSpendTheAccount() external {
        executor.callExecute(address(kernel));
        assertEq(attacker.balance, 1 ether, "installed executor should be able to execute");
    }

    function test_ExecutorHasNoAuthorityDuringItsOwnUninstall() external {
        vm.prank(address(ep));
        kernel.uninstallModule(MODULE_TYPE_EXECUTOR, address(executor), abi.encode(hex"", hex""));

        assertTrue(executor.reentryAttempted(), "onUninstall should have been called");
        assertFalse(executor.reentrySucceeded(), "executor must be revoked before its callback runs");
        assertEq(attacker.balance, 0, "no value should move during revocation");
        assertFalse(
            kernel.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(executor), ""), "executor should be uninstalled"
        );
    }

    /// @dev A reverting callback must not block revocation either.
    function test_UninstallCompletesEvenIfTheCallbackReverts() external {
        vm.mockCallRevert(address(executor), abi.encodeWithSignature("onUninstall(bytes)"), "nope");

        vm.prank(address(ep));
        kernel.uninstallModule(MODULE_TYPE_EXECUTOR, address(executor), abi.encode(hex"", hex""));

        assertFalse(
            kernel.isModuleInstalled(MODULE_TYPE_EXECUTOR, address(executor), ""), "executor should be uninstalled"
        );
    }
}
