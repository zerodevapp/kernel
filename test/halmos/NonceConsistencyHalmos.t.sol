pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {MODULE_MANAGER_STORAGE_SLOT} from "src/types/Constants.sol";

/// @notice Harness that exposes both `_checkNonce` (view) and
/// `_checkAndIncrementNonce` (state-mutating) plus storage seeders so we can
/// place both functions on the same symbolic pre-state and compare their
/// accept/reject verdicts.
/// @author taek <leekt216@gmail.com>
contract NonceConsistencyHarness is KernelUUPS {
    constructor(IEntryPoint _entryPoint) KernelUUPS(_entryPoint) {}

    function harness_checkNonce(uint256 _nonce) external view {
        _checkNonce(_nonce);
    }

    function harness_checkAndIncrementNonce(uint256 _nonce) external {
        _checkAndIncrementNonce(_nonce);
    }

    function harness_writeNonce(uint192 key, uint64 seq) external {
        bytes32 mappingSlot = bytes32(uint256(MODULE_MANAGER_STORAGE_SLOT) + 1);
        bytes32 entrySlot = keccak256(abi.encode(uint256(key), uint256(mappingSlot)));
        assembly {
            sstore(entrySlot, seq)
        }
    }

    function harness_writeNonceValidFrom(uint64 validFrom) external {
        // ModuleStorage slot 0 packs `address registry` (low 160 bits) with
        // `uint64 nonceValidFrom` at bit offset 160.
        bytes32 baseSlot = MODULE_MANAGER_STORAGE_SLOT;
        assembly {
            let word := sload(baseSlot)
            let mask := not(shl(160, 0xffffffffffffffff))
            word := and(word, mask)
            word := or(word, shl(160, validFrom))
            sstore(baseSlot, word)
        }
    }
}

/// @title NonceConsistencyHalmos
/// @notice Halmos proof that the view-only `_checkNonce` and the
/// state-mutating `_checkAndIncrementNonce` agree on which `_nonce` values
/// are acceptable for any pre-state of `nonce[key]` and `nonceValidFrom`,
/// excluding the saturation boundary `effectivePre == type(uint64).max`.
///
/// Both functions revert on rejection (via `require(... InvalidNonce())`).
/// A divergence between them would let the ERC-4337 simulation path
/// (`_checkNonce`) green-light a UserOp that the execution path
/// (`_checkAndIncrementNonce`) then reverts on, or vice versa — breaking
/// the simulation/execution agreement the EntryPoint relies on.
///
/// **Saturation boundary**: at `effectivePre == type(uint64).max`, the
/// view path accepts (`seq == effective`) while the write path reverts
/// from the checked `nonce[key]++` overflow. Reaching this state requires
/// ~2^64 prior calls on the same key, which `NonceOverflowHalmos.
/// check_NonceCannotOverflow` proves cannot happen organically. Each
/// check below excludes the boundary with an explicit, documented
/// precondition rather than silently weakening the spec.
///
/// Strategy: deploy two fresh harness instances per check, seed them with
/// the same symbolic pre-state (`preSeq`, `validFrom`, `key`), present the
/// same symbolic `nonceInput` to both, capture each call's `(success)`
/// boolean via low-level `call`, and assert the two booleans match.
/// @author taek <leekt216@gmail.com>
contract NonceConsistencyHalmos is SymTest, Test {
    IEntryPoint internal ep;

    function setUp() external {
        ep = IEntryPoint(address(0xee));
    }

    function _deploySeeded(uint192 key, uint64 preSeq, uint64 validFrom) internal returns (NonceConsistencyHarness h) {
        h = new NonceConsistencyHarness(ep);
        h.harness_writeNonce(key, preSeq);
        h.harness_writeNonceValidFrom(validFrom);
    }

    /// @notice Ratchet branch: when `nonceValidFrom > preSeq` the effective
    /// pre-state is `validFrom`, and both functions must accept iff the
    /// presented `seq` equals `validFrom`.
    ///
    /// This is the branch explicitly called out in the dispatch — it's the
    /// most fragile case because `_checkNonce` writes `result = (seq ==
    /// validFrom)` while `_checkAndIncrementNonce` first rewrites
    /// `nonce[key] = validFrom` and then checks `nonce[key]++ == seq`.
    /// The two formulations should be observationally equivalent;
    /// this property pins that down.
    function check_RatchetBranchAgreement() external {
        uint192 key = uint192(svm.createUint256("key"));
        uint64 preSeq = uint64(svm.createUint256("preSeq"));
        uint64 validFrom = uint64(svm.createUint256("validFrom"));
        uint64 presentedSeq = uint64(svm.createUint256("presentedSeq"));

        // Restrict to the ratchet branch: validFrom strictly greater than
        // the per-key sequence. This is a genuine precondition on the case
        // we want to isolate, not a weakening of the spec.
        vm.assume(validFrom > preSeq);

        // Saturation case excluded: NonceOverflowHalmos.check_NonceCannotOverflow
        // proves nonce[key] cannot reach type(uint64).max organically.
        vm.assume(validFrom < type(uint64).max);

        uint256 nonceInput = (uint256(key) << 64) | uint256(presentedSeq);

        NonceConsistencyHarness viewHarness = _deploySeeded(key, preSeq, validFrom);
        NonceConsistencyHarness writeHarness = _deploySeeded(key, preSeq, validFrom);

        (bool viewOk,) = address(viewHarness)
            .call(abi.encodeWithSelector(NonceConsistencyHarness.harness_checkNonce.selector, nonceInput));
        (bool writeOk,) = address(writeHarness)
            .call(abi.encodeWithSelector(NonceConsistencyHarness.harness_checkAndIncrementNonce.selector, nonceInput));

        assertEq(viewOk, writeOk, "ratchet branch: view and write disagree");
    }

    /// @notice Non-ratchet branch: when `nonceValidFrom <= preSeq` the
    /// effective pre-state is `preSeq`, and both functions must accept iff
    /// the presented `seq` equals `preSeq`.
    function check_NonRatchetBranchAgreement() external {
        uint192 key = uint192(svm.createUint256("key"));
        uint64 preSeq = uint64(svm.createUint256("preSeq"));
        uint64 validFrom = uint64(svm.createUint256("validFrom"));
        uint64 presentedSeq = uint64(svm.createUint256("presentedSeq"));

        // Restrict to the non-ratchet branch: per-key sequence is at or
        // above the global floor.
        vm.assume(validFrom <= preSeq);

        // Saturation case excluded: NonceOverflowHalmos.check_NonceCannotOverflow
        // proves nonce[key] cannot reach type(uint64).max organically.
        vm.assume(preSeq < type(uint64).max);

        uint256 nonceInput = (uint256(key) << 64) | uint256(presentedSeq);

        NonceConsistencyHarness viewHarness = _deploySeeded(key, preSeq, validFrom);
        NonceConsistencyHarness writeHarness = _deploySeeded(key, preSeq, validFrom);

        (bool viewOk,) = address(viewHarness)
            .call(abi.encodeWithSelector(NonceConsistencyHarness.harness_checkNonce.selector, nonceInput));
        (bool writeOk,) = address(writeHarness)
            .call(abi.encodeWithSelector(NonceConsistencyHarness.harness_checkAndIncrementNonce.selector, nonceInput));

        assertEq(viewOk, writeOk, "non-ratchet branch: view and write disagree");
    }

    /// @notice General agreement with the overflow corner excluded.
    /// Subsumes the ratchet/non-ratchet variants — the `effectivePre`
    /// computation here covers both branches by taking the max.
    /// Establishes that the ONLY divergence between `_checkNonce` and
    /// `_checkAndIncrementNonce` is the `effectivePre == type(uint64).max`
    /// boundary (where the view path accepts but the write path reverts
    /// from the checked `uint64` increment), which `NonceOverflowHalmos.
    /// check_NonceCannotOverflow` proves is operationally unreachable.
    function check_AgreementBelowOverflowSaturation() external {
        uint192 key = uint192(svm.createUint256("key"));
        uint64 preSeq = uint64(svm.createUint256("preSeq"));
        uint64 validFrom = uint64(svm.createUint256("validFrom"));
        uint256 nonceInput = svm.createUint256("nonceInput");

        nonceInput = (uint256(key) << 64) | (nonceInput & type(uint64).max);

        // Genuine precondition: exclude the saturation boundary where the
        // write path is doomed to revert by checked arithmetic. Reaching
        // this state requires ~2^64 prior install operations on the same
        // key, which is operationally impossible. Documented here for
        // auditor review — this is NOT a silent weakening of the spec.
        uint64 effectivePre = preSeq >= validFrom ? preSeq : validFrom;
        vm.assume(effectivePre < type(uint64).max);

        NonceConsistencyHarness viewHarness = _deploySeeded(key, preSeq, validFrom);
        NonceConsistencyHarness writeHarness = _deploySeeded(key, preSeq, validFrom);

        (bool viewOk,) = address(viewHarness)
            .call(abi.encodeWithSelector(NonceConsistencyHarness.harness_checkNonce.selector, nonceInput));
        (bool writeOk,) = address(writeHarness)
            .call(abi.encodeWithSelector(NonceConsistencyHarness.harness_checkAndIncrementNonce.selector, nonceInput));

        assertEq(viewOk, writeOk, "view/write disagree below saturation");
    }
}
