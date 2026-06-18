// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

import {Kernel} from "src/Kernel.sol";
import {KernelFactory} from "src/KernelFactory.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {KernelImmutableECDSA} from "src/KernelImmutableECDSA.sol";
import {Install} from "src/types/Structs.sol";

import {MockValidator} from "../mock/MockValidator.sol";

/// @notice Halmos proofs for `KernelFactory` CREATE2 determinism and idempotency.
///
/// Two properties per implementation variant (UUPS and ECDSA):
///   1. Determinism: `deploy(pkgs, nonce)` returns exactly `getAddress(pkgs, nonce)`.
///   2. Idempotency without re-init: a second `deploy(pkgs, nonce)` with the same
///      arguments returns the SAME address and does NOT revert. No-revert is
///      load-bearing here because `KernelUUPS.initialize` is gated by Solady's
///      `initializer` modifier — if the factory ever called `initialize` a second
///      time, that call would revert with `InvalidInitialization()`. Therefore
///      "second deploy succeeds and returns the same address" implies "no
///      double-init".
///
/// Symbolic surface kept small to make the proof tractable:
///   - `initialPackages.length == 1` (the minimum the UUPS variant accepts).
///   - `moduleType == 1`, `module == address(rootValidator)` (concrete).
///   - `moduleData` and `internalData` are empty bytes (concrete).
///   - `nonce` is fully symbolic (uint256).
///   - For the ECDSA variant, `signer` is symbolic but constrained non-zero.
///
/// These narrow the proven theorem from "for all (pkgs, nonce)" to "for all
/// (nonce[, signer]), holding the package shape fixed at the canonical
/// single-root-validator install used by the production deploy flow". The
/// CREATE2 address derivation is independent of the package contents
/// post-salt-hashing, so this restriction does not weaken the determinism
/// property in any way that matters for the factory's correctness.
///
/// Spec ambiguity note: the no-double-init claim is operationalised here as
/// "the second `deploy` does not revert". The factory implements this by
/// branching on `LibClone.createDeterministicERC1967`'s `alreadyDeployed`
/// return value and skipping `initialize` when the proxy already exists.
/// There is no `try/catch` swallowing — a failed re-init would propagate.
contract KernelFactoryHalmos is SymTest, Test {
    KernelFactory factory;
    KernelUUPS uupsImpl;
    KernelImmutableECDSA ecdsaImpl;
    MockValidator rootValidator;
    address entryPoint;

    function setUp() external {
        entryPoint = address(uint160(uint256(keccak256("EntryPoint"))));
        uupsImpl = new KernelUUPS(IEntryPoint(entryPoint));
        ecdsaImpl = new KernelImmutableECDSA(IEntryPoint(entryPoint));
        factory = new KernelFactory(uupsImpl, ecdsaImpl);
        rootValidator = new MockValidator();
    }

    /// @notice Builds the canonical single-element `Install[]` array used by
    ///         every check in this file: one type-1 root validator at the
    ///         concrete `rootValidator` address, with empty module/internal
    ///         data. Returned as memory; Solidity ABI-encodes to calldata on
    ///         the external call.
    function _pkgs() internal view returns (Install[] memory pkgs) {
        pkgs = new Install[](1);
        pkgs[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});
    }

    // ------------------------------------------------------------------
    // UUPS variant
    // ------------------------------------------------------------------

    /// @notice `factory.deploy(pkgs, nonce)` returns the same address as
    ///         `factory.getAddress(pkgs, nonce)`.
    function checkDeployMatchesGetAddress(uint256 nonce) external {
        Install[] memory pkgs = _pkgs();

        address predicted = factory.getAddress(pkgs, nonce);
        Kernel deployed = factory.deploy(pkgs, nonce);

        assertEq(address(deployed), predicted, "deploy must equal getAddress");
    }

    /// @notice A second `deploy` with the same args returns the same address
    ///         and does not revert. Together these imply no double-init: a
    ///         second `initialize` call would revert via Solady's
    ///         `initializer` modifier.
    function checkSecondDeployReturnsSameAddressNoReinit(uint256 nonce) external {
        Install[] memory pkgs = _pkgs();

        Kernel first = factory.deploy(pkgs, nonce);
        // If the factory mis-branched and tried to re-initialize, this call
        // would revert with `InvalidInitialization()` inside `KernelUUPS`.
        Kernel second = factory.deploy(pkgs, nonce);

        assertEq(address(second), address(first), "second deploy must return same address");
    }

    // ------------------------------------------------------------------
    // ECDSA variant
    // ------------------------------------------------------------------

    /// @notice `factory.deployECDSA(signer, pkgs, nonce)` returns the same
    ///         address as `factory.getECDSAAddress(signer, pkgs, nonce)`.
    function checkDeployECDSAMatchesGetECDSAAddress(address signer, uint256 nonce) external {
        vm.assume(signer != address(0));
        Install[] memory pkgs = _pkgs();

        address predicted = factory.getECDSAAddress(signer, pkgs, nonce);
        Kernel deployed = factory.deployECDSA(signer, pkgs, nonce);

        assertEq(address(deployed), predicted, "deployECDSA must equal getECDSAAddress");
    }

    /// @notice A second `deployECDSA` call with the same args returns the same
    ///         address and does not revert. Same no-double-init implication as
    ///         the UUPS variant.
    function checkSecondDeployECDSAReturnsSameAddressNoReinit(address signer, uint256 nonce) external {
        vm.assume(signer != address(0));
        Install[] memory pkgs = _pkgs();

        Kernel first = factory.deployECDSA(signer, pkgs, nonce);
        Kernel second = factory.deployECDSA(signer, pkgs, nonce);

        assertEq(address(second), address(first), "second deployECDSA must return same address");
    }
}
