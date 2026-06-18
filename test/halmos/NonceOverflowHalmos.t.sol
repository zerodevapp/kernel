pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {MODULE_MANAGER_STORAGE_SLOT} from "src/types/Constants.sol";

/// @notice Harness that exposes `_checkAndIncrementNonce` and lets us
/// symbolically seed `nonce[key]` / `nonceValidFrom` for proof.
/// @author taek <leekt216@gmail.com>
contract NonceHarness is KernelUUPS {
    constructor(IEntryPoint _entryPoint) KernelUUPS(_entryPoint) {}

    function harness_checkAndIncrementNonce(uint256 _nonce) external {
        _checkAndIncrementNonce(_nonce);
    }

    function harness_readNonce(uint192 key) external view returns (uint64 seq) {
        bytes32 mappingSlot = bytes32(uint256(MODULE_MANAGER_STORAGE_SLOT) + 1);
        bytes32 entrySlot = keccak256(abi.encode(uint256(key), uint256(mappingSlot)));
        assembly {
            seq := sload(entrySlot)
        }
    }

    function harness_writeNonce(uint192 key, uint64 seq) external {
        bytes32 mappingSlot = bytes32(uint256(MODULE_MANAGER_STORAGE_SLOT) + 1);
        bytes32 entrySlot = keccak256(abi.encode(uint256(key), uint256(mappingSlot)));
        assembly {
            sstore(entrySlot, seq)
        }
    }

    function harness_writeNonceValidFrom(uint64 validFrom) external {
        // ModuleStorage slot 0 contains `address registry` packed with `uint64 nonceValidFrom`.
        // address occupies bytes [0..20), nonceValidFrom occupies bytes [20..28) (offset 160 bits).
        bytes32 baseSlot = MODULE_MANAGER_STORAGE_SLOT;
        assembly {
            let word := sload(baseSlot)
            // clear the 64 bits at offset 160
            let mask := not(shl(160, 0xffffffffffffffff))
            word := and(word, mask)
            // OR in the new value
            word := or(word, shl(160, validFrom))
            sstore(baseSlot, word)
        }
    }

    function harness_readNonceValidFrom() external view returns (uint64 validFrom) {
        bytes32 baseSlot = MODULE_MANAGER_STORAGE_SLOT;
        assembly {
            let word := sload(baseSlot)
            validFrom := and(shr(160, word), 0xffffffffffffffff)
        }
    }
}

/// @notice Halmos proof that `_checkAndIncrementNonce` cannot drive the
/// per-key nonce above `type(uint64).max`. The Solidity-checked `++` on
/// the `uint64` mapping value must revert before any wrap occurs.
/// @author taek <leekt216@gmail.com>
contract NonceOverflowHalmos is SymTest, Test {
    NonceHarness harness;

    function setUp() external {
        address entryPoint = address(0xee);
        harness = new NonceHarness(IEntryPoint(entryPoint));
    }

    /// @notice Property: for every symbolic pre-state of `nonce[key]` and
    /// `nonceValidFrom` and every symbolic `_nonce` input, calling
    /// `_checkAndIncrementNonce` either reverts OR leaves the post-state
    /// strictly greater than the pre-state (no wrap-around).
    ///
    /// In particular, when the effective pre-state is `type(uint64).max`,
    /// the checked `++` must revert — the post-state cannot become 0.
    function check_NonceCannotOverflow() external {
        // Symbolic pre-state.
        uint192 key = uint192(svm.createUint256("key"));
        uint64 preSeq = uint64(svm.createUint256("preSeq"));
        uint64 validFrom = uint64(svm.createUint256("validFrom"));
        uint256 nonceInput = svm.createUint256("nonceInput");

        // Force the symbolic `_nonce` input to address the same `key` so the
        // proof binds the pre-state value to the post-state value. The low 64
        // bits of `nonceInput` (the seq the caller is presenting) remain fully
        // symbolic.
        nonceInput = (uint256(key) << 64) | (nonceInput & type(uint64).max);

        harness.harness_writeNonce(key, preSeq);
        harness.harness_writeNonceValidFrom(validFrom);

        // Effective pre-state used by `_checkAndIncrementNonce` is
        // `max(preSeq, validFrom)`.
        uint64 effectivePre = preSeq >= validFrom ? preSeq : validFrom;

        // Call the function. If it reverts, the overflow claim trivially
        // holds for this run.
        (bool ok,) = address(harness)
            .call(abi.encodeWithSelector(NonceHarness.harness_checkAndIncrementNonce.selector, nonceInput));

        if (ok) {
            // Post-state must be effectivePre + 1 with no wrap.
            // The implementation only succeeds when `effectivePre == seq` and
            // then writes `effectivePre + 1`. If `effectivePre` were
            // `type(uint64).max`, the checked `++` would have reverted, so
            // `ok` would be false.
            uint64 postSeq = harness.harness_readNonce(key);

            // No-wrap assertion: post == effectivePre + 1 (computed in
            // uint256 to make any uint64 wrap a counterexample). This
            // single equality refutes any overflow: if `++` had wrapped,
            // `postSeq` would be 0 while RHS would be `2^64`.
            assertEq(uint256(postSeq), uint256(effectivePre) + 1, "nonce wrapped or skipped");
        }
    }
}
