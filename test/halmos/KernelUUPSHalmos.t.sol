pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {LibClone} from "solady/utils/LibClone.sol";
import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";

/// @notice Symbolic verification of `KernelUUPS.upgradeToAndCall` access control.
///
/// Property under test: when called through an ERC1967 proxy whose implementation is
/// `KernelUUPS`, `upgradeToAndCall(newImpl, data)` MUST revert unless
/// `msg.sender == ENTRYPOINT || msg.sender == address(proxy)`. The internal
/// `_authorizeUpgrade` gate is `_onlyEntryPointOrSelf`, but the public entry path is
/// the only thing an external attacker can reach, so that is what we verify.
///
/// Note: Solady's `upgradeToAndCall` is the only public upgrade entry point — the
/// older `upgradeTo(address)` is NOT exposed by Solady v0.1.26, so it does not need
/// a separate check function. (See `dependencies/solady-0.1.26/src/utils/UUPSUpgradeable.sol`.)
contract KernelUUPSHalmos is SymTest, Test {
    KernelUUPS impl;
    address proxy;
    address entryPoint;

    function setUp() external {
        entryPoint = makeAddr("EntryPoint");
        impl = new KernelUUPS(IEntryPoint(entryPoint));
        // Deploy a real ERC1967 proxy pointing at the KernelUUPS template. This is
        // required because Solady's `upgradeToAndCall` carries an `onlyProxy` modifier
        // that reverts with `UnauthorizedCallContext()` when invoked on the
        // implementation directly — i.e. before the auth check would even be reached.
        proxy = LibClone.deployERC1967(address(impl));
    }

    /// @notice Any caller other than the EntryPoint or the proxy itself must be rejected.
    function checkUpgradeToAndCallRevertsForArbitraryCaller() external {
        address caller = svm.createAddress("caller");
        address newImpl = svm.createAddress("newImpl");
        vm.assume(caller != entryPoint);
        vm.assume(caller != proxy);

        vm.prank(caller);
        (bool ok,) = proxy.call(abi.encodeWithSelector(UUPSUpgradeable.upgradeToAndCall.selector, newImpl, ""));
        assertFalse(ok, "arbitrary caller must not be allowed to upgrade");
    }

    /// @notice The EntryPoint clears the access gate and successfully upgrades the proxy.
    ///
    /// We pass `newImpl = address(impl)` — a real `KernelUUPS` template whose
    /// `proxiableUUID()` returns the canonical ERC-1967 slot — so the full
    /// `upgradeToAndCall` path runs to completion (passing both the auth check and the
    /// `proxiableUUID` cross-check). Empty `data` skips the post-upgrade delegatecall.
    function checkUpgradeToAndCallSucceedsForEntryPoint() external {
        vm.prank(entryPoint);
        (bool ok,) = proxy.call(abi.encodeWithSelector(UUPSUpgradeable.upgradeToAndCall.selector, address(impl), ""));
        assertTrue(ok, "EntryPoint must be allowed to upgrade");
    }

    /// @notice The proxy itself (self-call) clears the access gate and successfully upgrades.
    function checkUpgradeToAndCallSucceedsForSelf() external {
        vm.prank(proxy);
        (bool ok,) = proxy.call(abi.encodeWithSelector(UUPSUpgradeable.upgradeToAndCall.selector, address(impl), ""));
        assertTrue(ok, "self-call must be allowed to upgrade");
    }
}
