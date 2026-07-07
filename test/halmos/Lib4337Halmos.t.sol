pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {Lib4337} from "src/lib/Lib4337.sol";

/// @notice Harness that exposes the internal-but-pure `intersectValidationData`
/// helper to Halmos. Halmos can only call external functions, so we wrap.
contract Lib4337Harness {
    function intersect(uint256 a, uint256 b) external pure returns (uint256) {
        return Lib4337.intersectValidationData(a, b);
    }
}

/// @notice Halmos proofs for `Lib4337.intersectValidationData` aggregator
/// precedence. The contract under test packs validation data as
///   [validAfter:48 | validUntil:48 | aggregator:160]
/// (bits 208..255, 160..207, 0..159 respectively). The aggregator field
/// follows ERC-4337 semantics:
///   0   = success
///   1   = failure (sigError sentinel)
///   >1  = aggregator address
///
/// The source comment in `Lib4337._intersectValidationData` enumerates six
/// precedence rules. Each rule below has its own `check…` function, plus
/// a combined check for the security-critical rule #3.
///
/// Format-mismatch behaviour (block-number vs timestamp validity) is
/// orthogonal to the aggregator question. To keep the aggregator search
/// space tractable we restrict the symbolic time bounds so neither side
/// uses block-number format. This is achieved by ANDing the high 96 bits
/// (the two uint48 time fields) with a mask that clears bit 47 of each.
contract Lib4337Halmos is SymTest, Test {
    Lib4337Harness internal harness;

    // Mask that clears MODE_BIT (bit 47) of both validAfter and validUntil
    // while leaving the rest of the 256-bit word untouched. Layout:
    //   bits 0..159   aggregator (left alone)
    //   bits 160..207 validUntil (clear bit 207 = 160+47)
    //   bits 208..255 validAfter (clear bit 255 = 208+47)
    uint256 internal constant CLEAR_MODE_BITS = ~((uint256(1) << 255) | (uint256(1) << 207));

    function setUp() external {
        harness = new Lib4337Harness();
    }

    // --------------------------------------------------------------------
    // Internal helpers
    // --------------------------------------------------------------------

    /// @dev Build a packed validationData word from raw components.
    function _pack(uint48 validAfter, uint48 validUntil, uint160 agg) internal pure returns (uint256 v) {
        v = uint256(agg);
        v |= uint256(validUntil) << 160;
        v |= uint256(validAfter) << 208;
    }

    /// @dev Extract the aggregator field from a packed word.
    function _agg(uint256 v) internal pure returns (uint160) {
        return uint160(v);
    }

    /// @dev Symbolic 256-bit word whose validity-format bits are forced off
    /// on both sides (so format-mismatch revert never triggers).
    function _symValidationData(string memory name) internal returns (uint256 v) {
        v = svm.createUint256(name);
        v &= CLEAR_MODE_BITS;
    }

    /// @dev Same as `_symValidationData` but with a fully symbolic aggregator
    /// constrained to a specific equivalence class (0, 1, or >1).
    function _symWithAgg(string memory name, uint160 forcedAgg) internal returns (uint256 v) {
        // Symbolic time bits but clear aggregator; then OR in the fixed agg.
        uint256 raw = svm.createUint256(name);
        raw &= CLEAR_MODE_BITS;
        // Clear low 160 bits then set them to forcedAgg.
        raw &= ~((uint256(1) << 160) - 1);
        v = raw | uint256(forcedAgg);
    }

    // --------------------------------------------------------------------
    // Rule 1: any failure (sentinel 1) ⇒ result aggregator == 1
    // --------------------------------------------------------------------

    /// preAgg == 1 ⇒ result aggregator must be 1, regardless of resAgg.
    function checkRule1_PreFailure() external {
        uint256 a = _symWithAgg("a_rule1pre", 1);
        uint256 b = _symValidationData("b_rule1pre");
        uint256 r = harness.intersect(a, b);
        assertEq(uint256(_agg(r)), uint256(1));
    }

    /// resAgg == 1 ⇒ result aggregator must be 1, regardless of preAgg.
    function checkRule1_ResFailure() external {
        uint256 a = _symValidationData("a_rule1res");
        uint256 b = _symWithAgg("b_rule1res", 1);
        uint256 r = harness.intersect(a, b);
        assertEq(uint256(_agg(r)), uint256(1));
    }

    // --------------------------------------------------------------------
    // Rule 2: both success (0) ⇒ result aggregator == 0
    // --------------------------------------------------------------------

    function checkRule2_BothSuccess() external {
        uint256 a = _symWithAgg("a_rule2", 0);
        uint256 b = _symWithAgg("b_rule2", 0);
        uint256 r = harness.intersect(a, b);
        assertEq(uint256(_agg(r)), uint256(0));
    }

    // --------------------------------------------------------------------
    // Rule 3 (SECURITY CRITICAL): preAgg > 1 && resAgg == 0 ⇒ result agg == preAgg
    // --------------------------------------------------------------------

    function checkRule3_PreserveAggregator() external {
        uint160 preAgg = uint160(svm.createUint(160, "preAgg_rule3"));
        vm.assume(preAgg > 1);

        uint256 a = _symWithAgg("a_rule3", preAgg);
        uint256 b = _symWithAgg("b_rule3", 0);

        uint256 r = harness.intersect(a, b);
        assertEq(uint256(_agg(r)), uint256(preAgg));
    }

    // --------------------------------------------------------------------
    // Rule 4: preAgg == 0 && resAgg > 1 ⇒ result agg == resAgg
    // --------------------------------------------------------------------

    function checkRule4_AdoptAggregator() external {
        uint160 resAgg = uint160(svm.createUint(160, "resAgg_rule4"));
        vm.assume(resAgg > 1);

        uint256 a = _symWithAgg("a_rule4", 0);
        uint256 b = _symWithAgg("b_rule4", resAgg);

        uint256 r = harness.intersect(a, b);
        assertEq(uint256(_agg(r)), uint256(resAgg));
    }

    // --------------------------------------------------------------------
    // Rule 5: same aggregator (both > 1, equal) ⇒ result agg == that aggregator
    // --------------------------------------------------------------------

    function checkRule5_SameAggregator() external {
        uint160 agg = uint160(svm.createUint(160, "agg_rule5"));
        vm.assume(agg > 1);

        uint256 a = _symWithAgg("a_rule5", agg);
        uint256 b = _symWithAgg("b_rule5", agg);

        uint256 r = harness.intersect(a, b);
        assertEq(uint256(_agg(r)), uint256(agg));
    }

    // --------------------------------------------------------------------
    // Rule 6: different aggregators (both > 1, unequal) ⇒ result agg == 1
    // --------------------------------------------------------------------

    function checkRule6_ConflictingAggregators() external {
        uint160 preAgg = uint160(svm.createUint(160, "preAgg_rule6"));
        uint160 resAgg = uint160(svm.createUint(160, "resAgg_rule6"));
        vm.assume(preAgg > 1);
        vm.assume(resAgg > 1);
        vm.assume(preAgg != resAgg);

        uint256 a = _symWithAgg("a_rule6", preAgg);
        uint256 b = _symWithAgg("b_rule6", resAgg);

        uint256 r = harness.intersect(a, b);
        assertEq(uint256(_agg(r)), uint256(1));
    }

    // --------------------------------------------------------------------
    // Combined SECURITY-CRITICAL property:
    //
    //   For all (preValidationData, validationRes) such that no validity
    //   format mismatch occurs, if preAgg > 1 and resAgg == 0 then the
    //   aggregator field of the result equals preAgg.
    //
    // This is the exact wording from the dispatch and is the regression
    // guard for the rule-3 bug: if the implementation ever falls back to
    // the "different aggregators ⇒ fail" branch when one side is 0, an
    // attacker could strip the aggregator and bypass aggregated validation.
    // --------------------------------------------------------------------

    function checkAggregatorPreservedWhenResAgg0() external {
        // Fully symbolic words; clear validity-format mode bits so
        // intersect() never reverts on format mismatch.
        uint256 a = svm.createUint256("a_secCrit") & CLEAR_MODE_BITS;
        uint256 b = svm.createUint256("b_secCrit") & CLEAR_MODE_BITS;

        uint160 preAgg = uint160(a);
        uint160 resAgg = uint160(b);

        vm.assume(preAgg > 1);
        vm.assume(resAgg == 0);

        uint256 r = harness.intersect(a, b);
        assertEq(uint256(_agg(r)), uint256(preAgg));
    }
}
