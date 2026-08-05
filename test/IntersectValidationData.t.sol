// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

import "src/lib/Lib4337.sol";

contract IntersectValidationDataTest is Test {
    // Helper to create validation data
    function createValidationData(uint48 validAfter, uint48 validUntil, address aggregator)
        internal
        pure
        returns (uint256)
    {
        return uint256(validAfter) << 208 | uint256(validUntil) << 160 | uint160(aggregator);
    }

    // Mock aggregator addresses
    address constant BLS_AGGREGATOR = address(0x1234);
    address constant SCHNORR_AGGREGATOR = address(0x5678);

    /**
     * TEST CATEGORY 1: Basic Success Cases
     */

    function test_BothStandardSuccess() public {
        uint256 pre = createValidationData(0, 0, address(0));
        uint256 res = createValidationData(0, 0, address(0));

        uint256 result = Lib4337._intersectValidationData(pre, res);

        assertEq(uint160(result), 0, "Should be standard success");
    }

    function test_PreAggregatorResSuccess() public {
        // CRITICAL TEST: This is the bug scenario from TOB-KERNEL-27
        uint256 pre = createValidationData(0, 0, BLS_AGGREGATOR);
        uint256 res = createValidationData(0, 0, address(0));

        uint256 result = Lib4337._intersectValidationData(pre, res);

        // FIXED: Should preserve BLS aggregator, not overwrite with address(0)
        assertEq(uint160(result), uint160(BLS_AGGREGATOR), "CRITICAL: Must preserve aggregator from previous policy");
    }

    function test_PreSuccessResAggregator() public {
        uint256 pre = createValidationData(0, 0, address(0));
        uint256 res = createValidationData(0, 0, BLS_AGGREGATOR);

        uint256 result = Lib4337._intersectValidationData(pre, res);

        assertEq(uint160(result), uint160(BLS_AGGREGATOR), "Should adopt aggregator from current policy");
    }

    function test_SameAggregator() public {
        uint256 pre = createValidationData(0, 0, BLS_AGGREGATOR);
        uint256 res = createValidationData(0, 0, BLS_AGGREGATOR);

        uint256 result = Lib4337._intersectValidationData(pre, res);

        assertEq(uint160(result), uint160(BLS_AGGREGATOR), "Should use the common aggregator");
    }

    /**
     * TEST CATEGORY 2: Failure Cases
     */

    function test_PreFailure() public {
        uint256 pre = createValidationData(0, 0, address(1)); // failure
        uint256 res = createValidationData(0, 0, address(0));

        uint256 result = Lib4337._intersectValidationData(pre, res);

        assertEq(uint160(result), 1, "Should propagate failure");
    }

    function test_ResFailure() public {
        uint256 pre = createValidationData(0, 0, address(0));
        uint256 res = createValidationData(0, 0, address(1)); // failure

        uint256 result = Lib4337._intersectValidationData(pre, res);

        assertEq(uint160(result), 1, "Should propagate failure");
    }

    function test_BothFailure() public {
        uint256 pre = createValidationData(0, 0, address(1));
        uint256 res = createValidationData(0, 0, address(1));

        uint256 result = Lib4337._intersectValidationData(pre, res);

        assertEq(uint160(result), 1, "Should remain failure");
    }

    function test_ConflictingAggregators() public {
        // Two different aggregators: cannot satisfy both
        uint256 pre = createValidationData(0, 0, BLS_AGGREGATOR);
        uint256 res = createValidationData(0, 0, SCHNORR_AGGREGATOR);

        uint256 result = Lib4337._intersectValidationData(pre, res);

        assertEq(uint160(result), 1, "Conflicting aggregators should fail validation");
    }

    /**
     * TEST CATEGORY 3: Time Bounds Intersection
     */

    function test_TimeBoundsWithAggregator() public {
        // validAfter: [100, 200], aggregator required
        uint256 pre = createValidationData(100, 300, BLS_AGGREGATOR);
        // validAfter: [200, 400], standard success
        uint256 res = createValidationData(200, 400, address(0));

        uint256 result = Lib4337._intersectValidationData(pre, res);

        // Should preserve aggregator
        assertEq(uint160(result), uint160(BLS_AGGREGATOR));

        // Should take most restrictive time bounds
        uint48 validAfter = uint48(result >> 208);
        uint48 validUntil = uint48(result >> 160);

        assertEq(validAfter, 200, "Should take maximum validAfter");
        assertEq(validUntil, 300, "Should take minimum validUntil");
    }

    /**
     * TEST CATEGORY 4: Real-World Scenarios
     */

    function test_BLSPolicyWithRateLimitPolicy() public {
        // Scenario from TOB-KERNEL-27:
        // Policy 1: BLS aggregation for gas efficiency
        // Policy 2: Rate limiting (returns success if within limits)

        uint256 blsValidation = createValidationData(0, 0, BLS_AGGREGATOR);
        uint256 rateLimitValidation = createValidationData(0, 0, address(0));

        uint256 result = Lib4337._intersectValidationData(blsValidation, rateLimitValidation);

        // CRITICAL: BLS aggregator must be preserved
        // EntryPoint should verify signatures via BLS aggregator
        assertEq(
            uint160(result), uint160(BLS_AGGREGATOR), "Rate limit policy should not remove BLS aggregation requirement"
        );
    }

    function test_MultipleStandardPolicies() public {
        // Multiple policies all returning standard success
        uint256 accumulated = createValidationData(0, 0, address(0));

        // Policy 1: Whitelist check
        accumulated = Lib4337._intersectValidationData(accumulated, createValidationData(0, 0, address(0)));

        // Policy 2: Daily limit check
        accumulated = Lib4337._intersectValidationData(accumulated, createValidationData(0, 0, address(0)));

        // Policy 3: Time lock check
        accumulated = Lib4337._intersectValidationData(accumulated, createValidationData(0, 0, address(0)));

        assertEq(uint160(accumulated), 0, "All standard checks should remain standard");
    }

    function test_AggregatorThenMultiplePolicies() public {
        // Start with aggregator requirement
        uint256 accumulated = createValidationData(0, 0, BLS_AGGREGATOR);

        // Then multiple standard policies
        accumulated = Lib4337._intersectValidationData(accumulated, createValidationData(0, 0, address(0)));
        accumulated = Lib4337._intersectValidationData(accumulated, createValidationData(0, 0, address(0)));
        accumulated = Lib4337._intersectValidationData(accumulated, createValidationData(0, 0, address(0)));

        // CRITICAL: Aggregator must survive through all intersections
        assertEq(
            uint160(accumulated),
            uint160(BLS_AGGREGATOR),
            "Aggregator requirement must persist through all policy checks"
        );
    }

    /**
     * TEST CATEGORY 5: Edge Cases
     */

    function test_ZeroIntersection() public {
        uint256 pre = 0;
        uint256 res = createValidationData(0, 0, BLS_AGGREGATOR);

        uint256 result = Lib4337._intersectValidationData(pre, res);

        // Short circuit: should return res
        assertEq(result, res, "Zero intersection should return non-zero value");
    }

    function test_ShortCircuitResZero() public {
        uint256 pre = createValidationData(0, 0, BLS_AGGREGATOR);
        uint256 res = 0;

        uint256 result = Lib4337._intersectValidationData(pre, res);

        // Short circuit: should return pre (preserving aggregator)
        assertEq(result, pre, "Zero res should preserve pre via short circuit");
    }

    function test_MaxTimeBounds() public {
        uint256 pre = createValidationData(0, type(uint48).max, BLS_AGGREGATOR);
        uint256 res = createValidationData(type(uint48).max, 0, address(0));

        uint256 result = Lib4337._intersectValidationData(pre, res);

        uint48 validAfter = uint48(result >> 208);
        uint48 validUntil = uint48(result >> 160);

        assertEq(validAfter, type(uint48).max);
        assertEq(validUntil, type(uint48).max);
        assertEq(uint160(result), uint160(BLS_AGGREGATOR));
    }

    /**
     * TEST CATEGORY 6: Regression Tests for Original Bug
     */

    function test_OriginalBugScenario() public {
        // This test specifically validates the fix for TOB-KERNEL-27

        // Original buggy behavior:
        // When preValidationData had an aggregator and validationRes had address(0),
        // the code would overwrite the aggregator with address(0)

        uint256 pre = createValidationData(0, 0, BLS_AGGREGATOR);
        uint256 res = createValidationData(0, 0, address(0));

        uint256 result = Lib4337._intersectValidationData(pre, res);

        // VERIFY FIX:
        // Old code: uint160(preValidationData) == 1 ? 1 : uint160(validationRes)
        //           → Would return 0 (wrong!)
        // New code: Should preserve preValidationData's aggregator
        //           → Should return BLS_AGGREGATOR (correct!)

        assertNotEq(uint160(result), 0, "Bug regression: aggregator was overwritten with address(0)");
        assertEq(uint160(result), uint160(BLS_AGGREGATOR), "Fixed: aggregator must be preserved");
    }

    function test_SecurityInvariant_AggregatorNeverDowngraded() public {
        // Security invariant: Once an aggregator is required, it cannot be removed
        // by subsequent policies returning address(0)

        uint256 withAggregator = createValidationData(0, 0, BLS_AGGREGATOR);
        uint256 standardSuccess = createValidationData(0, 0, address(0));

        // Test multiple intersections
        uint256 result1 = Lib4337._intersectValidationData(withAggregator, standardSuccess);
        uint256 result2 = Lib4337._intersectValidationData(result1, standardSuccess);
        uint256 result3 = Lib4337._intersectValidationData(result2, standardSuccess);

        // All results must maintain the aggregator
        assertEq(uint160(result1), uint160(BLS_AGGREGATOR));
        assertEq(uint160(result2), uint160(BLS_AGGREGATOR));
        assertEq(uint160(result3), uint160(BLS_AGGREGATOR));
    }

    /**
     * TEST CATEGORY 7: Fuzz Testing
     */

    // Mask to clear highest bit (MODE_BIT) to ensure timestamp format
    uint48 constant MODE_BIT = 0x800000000000;
    uint48 constant TIMESTAMP_MASK = 0x7fffffffffff;

    function testFuzz_AggregatorNeverDowngradedToZero(
        uint48 validAfter1,
        uint48 validUntil1,
        uint48 validAfter2,
        uint48 validUntil2,
        address aggregator
    ) public {
        vm.assume(uint160(aggregator) > 1); // Valid aggregator (not 0 or 1)

        // Ensure consistent timestamp format by clearing MODE_BIT
        validAfter1 = validAfter1 & TIMESTAMP_MASK;
        validUntil1 = validUntil1 & TIMESTAMP_MASK;
        validAfter2 = validAfter2 & TIMESTAMP_MASK;
        validUntil2 = validUntil2 & TIMESTAMP_MASK;

        uint256 withAgg = createValidationData(validAfter1, validUntil1, aggregator);
        uint256 withoutAgg = createValidationData(validAfter2, validUntil2, address(0));

        uint256 result = Lib4337._intersectValidationData(withAgg, withoutAgg);

        // CRITICAL INVARIANT: aggregator must be preserved
        assertEq(uint160(result), uint160(aggregator), "Fuzz test failed: aggregator was downgraded");
    }

    function testFuzz_FailurePropagates(
        uint48 validAfter1,
        uint48 validUntil1,
        uint48 validAfter2,
        uint48 validUntil2,
        bool firstFails
    ) public {
        // Ensure consistent timestamp format by clearing MODE_BIT
        validAfter1 = validAfter1 & TIMESTAMP_MASK;
        validUntil1 = validUntil1 & TIMESTAMP_MASK;
        validAfter2 = validAfter2 & TIMESTAMP_MASK;
        validUntil2 = validUntil2 & TIMESTAMP_MASK;

        address agg1 = firstFails ? address(1) : address(0);
        address agg2 = firstFails ? address(0) : address(1);

        uint256 val1 = createValidationData(validAfter1, validUntil1, agg1);
        uint256 val2 = createValidationData(validAfter2, validUntil2, agg2);

        uint256 result = Lib4337._intersectValidationData(val1, val2);

        // Failure must propagate
        assertEq(uint160(result), 1, "Failure must propagate");
    }

    /**
     * TEST CATEGORY 8: Block Number Format Tests (EP v0.9)
     */

    function test_BlockNumberFormatBothMatch() public {
        // Both use block number format (highest bit set on both validAfter and validUntil)
        uint48 blockAfter1 = 100 | MODE_BIT;
        uint48 blockUntil1 = 200 | MODE_BIT;
        uint48 blockAfter2 = 150 | MODE_BIT;
        uint48 blockUntil2 = 250 | MODE_BIT;

        uint256 val1 = createValidationData(blockAfter1, blockUntil1, address(0));
        uint256 val2 = createValidationData(blockAfter2, blockUntil2, address(0));

        uint256 result = Lib4337._intersectValidationData(val1, val2);

        uint48 validAfter = uint48(result >> 208);
        uint48 validUntil = uint48(result >> 160);

        // Should take max validAfter and min validUntil
        assertEq(validAfter, 150 | MODE_BIT, "Should take max validAfter");
        assertEq(validUntil, 200 | MODE_BIT, "Should take min validUntil");
    }

    function test_FormatMismatchReverts() public {
        // First uses timestamp format
        uint256 timestampFormat = createValidationData(100, 200, address(0));
        // Second uses block number format
        uint256 blockFormat = createValidationData(100 | MODE_BIT, 200 | MODE_BIT, address(0));

        // Use try/catch since vm.expectRevert doesn't work with internal pure functions
        try this.callIntersect(timestampFormat, blockFormat) {
            fail("Should have reverted with ValidityFormatMismatch");
        } catch (bytes memory reason) {
            assertEq(bytes4(reason), bytes4(keccak256("ValidityFormatMismatch()")));
        }
    }

    function test_FormatMismatchRevertsReverse() public {
        // First uses block number format
        uint256 blockFormat = createValidationData(100 | MODE_BIT, 200 | MODE_BIT, address(0));
        // Second uses timestamp format
        uint256 timestampFormat = createValidationData(100, 200, address(0));

        // Use try/catch since vm.expectRevert doesn't work with internal pure functions
        try this.callIntersect(blockFormat, timestampFormat) {
            fail("Should have reverted with ValidityFormatMismatch");
        } catch (bytes memory reason) {
            assertEq(bytes4(reason), bytes4(keccak256("ValidityFormatMismatch()")));
        }
    }

    // External wrapper to enable try/catch
    function callIntersect(uint256 a, uint256 b) external pure returns (uint256) {
        return Lib4337._intersectValidationData(a, b);
    }

    function testFuzz_BlockNumberFormatConsistent(
        uint48 validAfter1,
        uint48 validUntil1,
        uint48 validAfter2,
        uint48 validUntil2
    ) public {
        // Mask to lower bits then add MODE_BIT to ensure block number format
        validAfter1 = (validAfter1 & TIMESTAMP_MASK) | MODE_BIT;
        validUntil1 = (validUntil1 & TIMESTAMP_MASK) | MODE_BIT;
        validAfter2 = (validAfter2 & TIMESTAMP_MASK) | MODE_BIT;
        validUntil2 = (validUntil2 & TIMESTAMP_MASK) | MODE_BIT;

        uint256 val1 = createValidationData(validAfter1, validUntil1, address(0));
        uint256 val2 = createValidationData(validAfter2, validUntil2, address(0));

        // Should not revert when both use same format
        uint256 result = Lib4337._intersectValidationData(val1, val2);

        // Result should maintain block number format
        uint48 resultAfter = uint48(result >> 208);
        uint48 resultUntil = uint48(result >> 160);

        assertTrue(resultAfter & MODE_BIT != 0, "Result validAfter should have MODE_BIT");
        assertTrue(resultUntil & MODE_BIT != 0, "Result validUntil should have MODE_BIT");
    }

    /**
     * TEST CATEGORY 9: Regression — validity-format ordering (audit M-03)
     *
     * The format check must run AFTER `validUntil == 0 -> max` normalization, the
     * aggregator failure/conflict must resolve BEFORE the format check, and a neutral
     * `[0, max]` range must be exempt from the format check.
     */

    // An unbounded block range encodes validUntil = 0. Before the fix this was classified
    // as timestamp format (raw validUntil = 0 lacks MODE_BIT), so pairing it with a future
    // timestamp range passed the format check and then dropped the future timestamp start
    // (MODE_BIT >> any real timestamp, so max() kept the block validAfter). After the fix the
    // range normalizes to [MODE_BIT|block, max] (block format) and the mismatched intersection
    // is rejected instead of silently producing an already-valid result.
    function test_Regression_UnboundedBlockRangeVsFutureTimestampReverts() public {
        uint256 unboundedBlock = createValidationData(100 | MODE_BIT, 0, address(0));
        uint256 futureTimestamp = createValidationData(2_000_000_000, 0, address(0));

        try this.callIntersect(unboundedBlock, futureTimestamp) returns (uint256 result) {
            // The dangerous pre-fix outcome: no revert AND the future start is dropped.
            uint48 resultAfter = uint48(result >> 208);
            assertFalse(
                resultAfter == (100 | MODE_BIT),
                "M-03: future timestamp start dropped by misclassified unbounded block range"
            );
            fail("M-03: mismatched block/timestamp intersection must revert, not silently merge");
        } catch (bytes memory reason) {
            assertEq(bytes4(reason), bytes4(keccak256("ValidityFormatMismatch()")));
        }
    }

    // A signature-failure operand (aggregator == 1) has all-zero raw time bounds. Before the
    // fix, pairing it with a block-format range hit the format `revert` before the aggregator
    // logic ran. After the fix the failure short-circuits and returns SIG_VALIDATION_FAILED.
    function test_Regression_FailureOperandDoesNotRevertOnFormatMismatch() public {
        uint256 blockValid = createValidationData(100 | MODE_BIT, 200 | MODE_BIT, address(0));
        uint256 failure = createValidationData(0, 0, address(1));

        // Must not revert; must return failure.
        uint256 result = Lib4337._intersectValidationData(blockValid, failure);
        assertEq(uint160(result), 1, "M-03: signature failure must be returned, not reverted");

        // Symmetric ordering.
        uint256 resultRev = Lib4337._intersectValidationData(failure, blockValid);
        assertEq(uint160(resultRev), 1, "M-03: signature failure must be returned, not reverted (reverse)");
    }

    // A neutral [0, max] range carries no restriction and no format. It must intersect with a
    // block-format range without a spurious ValidityFormatMismatch (its normalized validUntil
    // has MODE_BIT set, which would otherwise misclassify it as block/timestamp inconsistently).
    function test_Regression_NeutralRangeWithBlockRangeDoesNotRevert() public {
        // Neutral range carrying only an aggregator (validAfter = validUntil = 0).
        uint256 neutral = createValidationData(0, 0, BLS_AGGREGATOR);
        uint256 blockRange = createValidationData(100 | MODE_BIT, 200 | MODE_BIT, address(0));

        uint256 result = Lib4337._intersectValidationData(neutral, blockRange);

        assertEq(uint160(result), uint160(BLS_AGGREGATOR), "M-03: aggregator must survive neutral intersection");
        assertEq(uint48(result >> 208), 100 | MODE_BIT, "M-03: block validAfter must be preserved");
        assertEq(uint48(result >> 160), 200 | MODE_BIT, "M-03: block validUntil must be preserved");
    }
}

