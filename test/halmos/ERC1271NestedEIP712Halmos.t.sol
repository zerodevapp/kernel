// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {ERC1271} from "src/lib/ERC1271.sol";

/// @notice Halmos harness exposing the nested EIP-712 entry points and a
///         controllable mock for the abstract inner ERC-1271 verifier. The
///         override reads `innerResult` from storage; the property test
///         pins it to `false` so any reachable path that returns `true`
///         from the outer function would constitute a verifier bypass.
/// @author taek <leekt216@gmail.com>
contract NestedEIP712Harness is ERC1271 {
    bool public innerResult;

    function setInnerResult(bool v) external {
        innerResult = v;
    }

    /// @dev Override the abstract Solady hook with a concrete (non-changing)
    ///      domain so Halmos can resolve `eip712Domain()` calls during
    ///      symbolic execution without driving the encoder paths.
    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "KernelHarness";
        version = "1";
    }

    /// @dev Overrides the abstract inner verifier hook. Reads `innerResult`
    ///      from storage; remains `view` to match the base mutability.
    function _erc1271IsValidSignatureNowCalldata(bytes32, bytes calldata) internal view override returns (bool) {
        return innerResult;
    }

    function callNestedEIP712(bytes32 hash, bytes calldata signature) external view returns (bool) {
        return _erc1271IsValidSignatureViaNestedEIP712(hash, signature);
    }

    function callNestedEIP712Replayable(bytes32 hash, bytes calldata signature) external view returns (bool) {
        return _erc1271IsValidSignatureViaNestedEIP712Replayable(hash, signature);
    }
}

/// @title ERC1271NestedEIP712Halmos
/// @notice Halmos partial proof of FV gap-audit property #15.
///
///         Property statement:
///             `_erc1271IsValidSignatureViaNestedEIP712` (and the Replayable
///             variant) return `true` ONLY when the inner
///             `_erc1271IsValidSignatureNowCalldata(hash, signature)` returns
///             `true`.
///
///         Stated contrapositively (the form proved here, because it is the
///         strongest single-statement form that covers every reachable path):
///
///             innerResult == false  ==>  outerResult == false
///
///         Both functions have exactly one return site
///         (`src/lib/ERC1271.sol:239` and `:326`), namely
///         `result = _erc1271IsValidSignatureNowCalldata(...)`. The
///         TypedDataSign workflow, the PersonalSign fallback, and the
///         corrupted-`d` branch at line 232 all funnel through this single
///         call — therefore proving the above implication for every
///         enumerated signature length proves the property holds at every
///         concrete length we exercise.
///
///         Each `check_*` function enumerates a concrete signature length
///         AND pins the trailing 2 bytes of the signature to a concrete
///         value. Pinning the trailing 2 bytes is required to satisfy
///         Halmos's CALLDATACOPY backend, which rejects symbolic copy
///         offsets (the assembly computes its copy offset as
///         `signature.offset + sub(signature.length, 0x42 + c)`, where `c`
///         is the trailing 2 bytes; if `c` is symbolic, the offset is
///         symbolic and Halmos raises `NotConcreteError`). Every byte
///         except the trailing two remains fully symbolic.
///
///         Enumerated cases (proved here, both variants):
///             - L=0,   c=N/A — degenerate signature (out-of-bounds reads
///                              return 0; PersonalSign branch via
///                              `iszero(c)`).
///             - L=65,  c=0   — PersonalSign branch via `iszero(c)`.
///                              Canonical ECDSA-shape signature.
///             - L=100, c=0   — PersonalSign branch via `iszero(c)`,
///                              mid-sized signature body.
///
///         Each check pins `innerResult = false` (default on fresh deploy)
///         and asserts the outer call returns `false`.
///
///         What is NOT proved by this Halmos partial:
///             - The TypedDataSign branch (where the for-loop falls through
///               to the typehash construction). Even with `c` pinned
///               concrete, Halmos hits `NotConcreteError: symbolic SHA3
///               data size` because the `contentsName`-scan loop computes
///               the keccak input length from symbolic byte-equality
///               checks against ')' and '('. The companion Kontrol
///               scaffold at
///               `test/kontrol/ERC1271NestedEIP712Kontrol.t.sol` is the
///               complementary track for that branch.
///
/// @author taek <leekt216@gmail.com>
contract ERC1271NestedEIP712Halmos is SymTest, Test {
    NestedEIP712Harness internal harness;

    function setUp() external {
        harness = new NestedEIP712Harness();
        // Default storage is `false`, but be explicit: the property is
        // "outer returns true implies inner returned true". By forcing the
        // inner verifier to reject we prove the contrapositive — no outer
        // path returns `true` without inner approval.
        harness.setInnerResult(false);
    }

    /* -------------------------------------------------------------------- */
    /*  Standard variant (`_erc1271IsValidSignatureViaNestedEIP712`)        */
    /* -------------------------------------------------------------------- */

    /// @notice Length 0: degenerate signature. The for-loop reads `c` from
    ///         calldata bytes outside the signature region; we still must
    ///         end up in the PersonalSign branch and ultimately in the
    ///         inner verifier (which is pinned to false).
    function check_NestedEIP712_Length0(bytes32 hash) external {
        bytes memory sig = svm.createBytes(0, "sig");
        bool outer = harness.callNestedEIP712(hash, sig);
        assert(!outer);
    }

    /// @notice Length 65: canonical ECDSA `r || s || v` length. With high
    ///         probability `c` (read from last 2 bytes) makes
    ///         `l = 0x42 + c > 65`, forcing the PersonalSign branch.
    ///         To keep Halmos's CALLDATACOPY backend happy (it requires
    ///         syntactically-concrete copy offsets), we pin the trailing 2
    ///         bytes to zero. This forces `c == 0`, which forces the
    ///         `iszero(c)` disjunct of the PersonalSign branch — covering
    ///         the most common ECDSA-signature shape.
    function check_NestedEIP712_Length65_PersonalSignBranch(bytes32 hash) external {
        bytes memory sig = svm.createBytes(65, "sig");
        // Force `c = uint16(last 2 bytes) == 0` → PersonalSign branch via
        // `iszero(c)`. Concretely pinning these two bytes is the strongest
        // restriction Halmos accepts here without weakening the property
        // statement: the property still says "outer => inner approved" for
        // *every* 65-byte signature whose last 2 bytes are zero.
        sig[63] = 0x00;
        sig[64] = 0x00;
        bool outer = harness.callNestedEIP712(hash, sig);
        assert(!outer);
    }

    /// @notice Length 100 with `c == 0`: forces the PersonalSign branch via
    ///         `iszero(c)`. Body of signature (first 98 bytes) stays
    ///         symbolic — exercises the `_hashTypedData` post-processing.
    function check_NestedEIP712_Length100_PersonalSignBranch(bytes32 hash) external {
        bytes memory sig = svm.createBytes(100, "sig");
        sig[98] = 0x00;
        sig[99] = 0x00;
        bool outer = harness.callNestedEIP712(hash, sig);
        assert(!outer);
    }

    // -------------------------------------------------------------------- //
    // TypedDataSign branch — NOT PROVED HERE.                              //
    //                                                                     //
    // Attempted lengths (67 with c=1, 100 with c=32) pin `c` so the        //
    // CALLDATACOPY offset is concrete, but Halmos still hits               //
    // `NotConcreteError: symbolic SHA3 data size` because the              //
    // `contentsName`-scan loop computes the keccak input length            //
    // (`sub(add(p, c), m)`) from symbolic byte-equality checks against     //
    // ')' and '('. Halmos's keccak handler requires a syntactically        //
    // concrete size argument.                                              //
    //                                                                     //
    // The TypedDataSign side is therefore proved by the companion          //
    // Kontrol scaffold at                                                  //
    // `test/kontrol/ERC1271NestedEIP712Kontrol.t.sol` rather than here.    //
    // -------------------------------------------------------------------- //

    /* -------------------------------------------------------------------- */
    /*  Replayable variant                                                  */
    /*  (`_erc1271IsValidSignatureViaNestedEIP712Replayable`)               */
    /* -------------------------------------------------------------------- */

    function check_NestedEIP712Replayable_Length0(bytes32 hash) external {
        bytes memory sig = svm.createBytes(0, "sig");
        bool outer = harness.callNestedEIP712Replayable(hash, sig);
        assert(!outer);
    }

    function check_NestedEIP712Replayable_Length65_PersonalSignBranch(bytes32 hash) external {
        bytes memory sig = svm.createBytes(65, "sig");
        sig[63] = 0x00;
        sig[64] = 0x00;
        bool outer = harness.callNestedEIP712Replayable(hash, sig);
        assert(!outer);
    }

    function check_NestedEIP712Replayable_Length100_PersonalSignBranch(bytes32 hash) external {
        bytes memory sig = svm.createBytes(100, "sig");
        sig[98] = 0x00;
        sig[99] = 0x00;
        bool outer = harness.callNestedEIP712Replayable(hash, sig);
        assert(!outer);
    }

    // TypedDataSign branch on the Replayable variant is also out of scope
    // for Halmos for the same `NotConcreteError: symbolic SHA3 data size`
    // reason. See the comment above the corresponding TypedDataSign gap on
    // the standard variant.
}
