// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {Lib4337Harness} from "../mock/Lib4337Harness.sol";
import {Lib4337} from "src/lib/Lib4337.sol";
import {ValidityFormatMismatch} from "src/types/Error.sol";

/// @notice Unit tests for Lib4337.intersectValidationData covering all quadrants
/// and edge cases for aggregator handling.
contract Lib4337CoverageTest is Test {
    Lib4337Harness harness;

    function setUp() public {
        harness = new Lib4337Harness();
    }

    // =========================================================================
    // parseValidationData
    // =========================================================================

    function test_parseValidationData_WhenZero_ShouldReturnDefaultValues() public view {
        (uint48 validAfter, uint48 validUntil, address result) = harness.parseValidationData(0);
        assertEq(validAfter, 0, "validAfter should be 0");
        assertEq(validUntil, type(uint48).max, "validUntil should be max when encoded as 0");
        assertEq(result, address(0), "result should be address(0)");
    }

    function test_parseValidationData_WhenSigValidationFailed_ShouldReturnAddress1() public view {
        (uint48 validAfter, uint48 validUntil, address result) = harness.parseValidationData(1);
        assertEq(validAfter, 0, "validAfter should be 0");
        assertEq(validUntil, type(uint48).max, "validUntil should be max");
        assertEq(result, address(1), "result should be address(1) for SIG_VALIDATION_FAILED");
    }

    function test_parseValidationData_WhenTimeBoundsSet_ShouldReturnCorrectBounds() public view {
        // Pack: validAfter=100, validUntil=200, result=address(0)
        uint256 packed = (uint256(100) << 208) | (uint256(200) << 160);
        (uint48 validAfter, uint48 validUntil, address result) = harness.parseValidationData(packed);
        assertEq(validAfter, 100, "validAfter should be 100");
        assertEq(validUntil, 200, "validUntil should be 200");
        assertEq(result, address(0), "result should be address(0)");
    }

    // =========================================================================
    // checkValidation
    // =========================================================================

    function test_checkValidation_WhenSuccess_ShouldReturnTrue() public view {
        assertTrue(harness.checkValidation(0), "Zero validationData means success");
    }

    function test_checkValidation_WhenFailed_ShouldReturnFalse() public view {
        assertFalse(harness.checkValidation(1), "SIG_VALIDATION_FAILED should return false");
    }

    function test_checkValidation_WhenExpired_ShouldReturnFalse() public {
        // Set validUntil in the past
        vm.warp(1000);
        uint256 packed = (uint256(0) << 208) | (uint256(500) << 160); // validUntil = 500, now = 1000
        assertFalse(harness.checkValidation(packed), "Expired validUntil should return false");
    }

    function test_checkValidation_WhenNotYetValid_ShouldReturnFalse() public {
        // Set validAfter in the future
        vm.warp(100);
        uint256 packed = (uint256(500) << 208) | (uint256(1000) << 160); // validAfter = 500, now = 100
        assertFalse(harness.checkValidation(packed), "Future validAfter should return false");
    }

    // =========================================================================
    // intersectValidationData — identity cases (a=0 or b=0)
    // =========================================================================

    function test_intersectValidationData_WhenAIsZero_ShouldReturnB() public view {
        uint256 b = (uint256(100) << 208) | (uint256(200) << 160);
        uint256 result = harness.intersectValidationData(0, b);
        assertEq(result, b, "When a=0, result should be b");
    }

    function test_intersectValidationData_WhenBIsZero_ShouldReturnA() public view {
        uint256 a = (uint256(100) << 208) | (uint256(200) << 160);
        uint256 result = harness.intersectValidationData(a, 0);
        assertEq(result, a, "When b=0, result should be a");
    }

    function test_intersectValidationData_WhenBothZero_ShouldReturnZero() public view {
        uint256 result = harness.intersectValidationData(0, 0);
        assertEq(result, 0, "Both zero should return zero");
    }

    // =========================================================================
    // intersectValidationData — time bounds quadrants
    // =========================================================================

    function test_intersectValidationData_WhenBothValid_ShouldIntersectTimeBounds() public view {
        // a: validAfter=100, validUntil=500
        // b: validAfter=200, validUntil=400
        // Expected: validAfter=max(100,200)=200, validUntil=min(500,400)=400
        uint256 a = (uint256(100) << 208) | (uint256(500) << 160);
        uint256 b = (uint256(200) << 208) | (uint256(400) << 160);

        uint256 result = harness.intersectValidationData(a, b);
        (uint48 validAfter, uint48 validUntil, address res) = harness.parseValidationData(result);

        assertEq(validAfter, 200, "validAfter should be max(100,200)=200");
        assertEq(validUntil, 400, "validUntil should be min(500,400)=400");
        assertEq(res, address(0), "Both success => result address(0)");
    }

    function test_intersectValidationData_WhenFirstExpired_ShouldPreserveNarrowerBounds() public view {
        // a: validAfter=0, validUntil=100 (expired when block.timestamp > 100)
        // b: validAfter=0, validUntil=200
        // Expected: validUntil=min(100,200)=100
        uint256 a = (uint256(0) << 208) | (uint256(100) << 160);
        uint256 b = (uint256(0) << 208) | (uint256(200) << 160);

        uint256 result = harness.intersectValidationData(a, b);
        (uint48 validAfter, uint48 validUntil,) = harness.parseValidationData(result);

        assertEq(validAfter, 0, "validAfter should be 0");
        assertEq(validUntil, 100, "validUntil should be min(100,200)=100");
    }

    function test_intersectValidationData_WhenSecondExpired_ShouldPreserveNarrowerBounds() public view {
        // a: validAfter=0, validUntil=500
        // b: validAfter=0, validUntil=50
        uint256 a = (uint256(0) << 208) | (uint256(500) << 160);
        uint256 b = (uint256(0) << 208) | (uint256(50) << 160);

        uint256 result = harness.intersectValidationData(a, b);
        (, uint48 validUntil,) = harness.parseValidationData(result);

        assertEq(validUntil, 50, "validUntil should be min(500,50)=50");
    }

    function test_intersectValidationData_WhenBothExpiredWithDifferentBounds_ShouldPickSmaller() public view {
        // a: validAfter=50, validUntil=100
        // b: validAfter=80, validUntil=90
        // Expected: validAfter=max(50,80)=80, validUntil=min(100,90)=90
        uint256 a = (uint256(50) << 208) | (uint256(100) << 160);
        uint256 b = (uint256(80) << 208) | (uint256(90) << 160);

        uint256 result = harness.intersectValidationData(a, b);
        (uint48 validAfter, uint48 validUntil,) = harness.parseValidationData(result);

        assertEq(validAfter, 80, "validAfter should be max(50,80)=80");
        assertEq(validUntil, 90, "validUntil should be min(100,90)=90");
    }

    function test_intersectValidationData_WhenValidUntilIsZero_ShouldTreatAsMaxUint48() public view {
        // validUntil=0 means "no expiry" (converted to type(uint48).max internally)
        // a: validAfter=0, validUntil=0 (no expiry)
        // b: validAfter=0, validUntil=500
        uint256 a = 1; // SIG_VALIDATION_FAILED with validUntil=0
        uint256 b = (uint256(500) << 160) | 1; // SIG_VALIDATION_FAILED with validUntil=500

        uint256 result = harness.intersectValidationData(a, b);
        (, uint48 validUntil,) = harness.parseValidationData(result);

        assertEq(validUntil, 500, "validUntil should be min(max,500)=500");
    }

    // =========================================================================
    // intersectValidationData — aggregator logic
    // =========================================================================

    function test_intersectValidationData_WhenBothSuccess_ShouldReturnSuccess() public view {
        // Both have result=address(0) => success
        uint256 a = (uint256(10) << 208) | (uint256(100) << 160);
        uint256 b = (uint256(20) << 208) | (uint256(200) << 160);

        uint256 result = harness.intersectValidationData(a, b);
        (,, address res) = harness.parseValidationData(result);
        assertEq(res, address(0), "Both success => aggregator address(0)");
    }

    function test_intersectValidationData_WhenFirstFailed_ShouldReturnFailed() public view {
        // a has result=1 (failure), b has result=0 (success)
        uint256 a = (uint256(10) << 208) | (uint256(100) << 160) | 1;
        uint256 b = (uint256(20) << 208) | (uint256(200) << 160);

        uint256 result = harness.intersectValidationData(a, b);
        (,, address res) = harness.parseValidationData(result);
        assertEq(res, address(1), "Any failure => aggregator address(1)");
    }

    function test_intersectValidationData_WhenSecondFailed_ShouldReturnFailed() public view {
        // a has result=0, b has result=1
        uint256 a = (uint256(10) << 208) | (uint256(100) << 160);
        uint256 b = (uint256(20) << 208) | (uint256(200) << 160) | 1;

        uint256 result = harness.intersectValidationData(a, b);
        (,, address res) = harness.parseValidationData(result);
        assertEq(res, address(1), "Any failure => aggregator address(1)");
    }

    function test_intersectValidationData_WhenBothFailed_ShouldReturnFailed() public view {
        uint256 a = (uint256(10) << 208) | (uint256(100) << 160) | 1;
        uint256 b = (uint256(20) << 208) | (uint256(200) << 160) | 1;

        uint256 result = harness.intersectValidationData(a, b);
        (,, address res) = harness.parseValidationData(result);
        assertEq(res, address(1), "Both failure => aggregator address(1)");
    }

    function test_intersectValidationData_WhenAggregatorAndSuccess_ShouldPreserveAggregator() public view {
        // a has aggregator=address(0x1234), b has success
        address aggregator = address(0x1234);
        uint256 a = (uint256(10) << 208) | (uint256(100) << 160) | uint160(aggregator);
        uint256 b = (uint256(20) << 208) | (uint256(200) << 160);

        uint256 result = harness.intersectValidationData(a, b);
        (,, address res) = harness.parseValidationData(result);
        assertEq(res, aggregator, "Aggregator + success => preserve aggregator");
    }

    function test_intersectValidationData_WhenSuccessAndAggregator_ShouldAdoptAggregator() public view {
        // a has success, b has aggregator=address(0x5678)
        address aggregator = address(0x5678);
        uint256 a = (uint256(10) << 208) | (uint256(100) << 160);
        uint256 b = (uint256(20) << 208) | (uint256(200) << 160) | uint160(aggregator);

        uint256 result = harness.intersectValidationData(a, b);
        (,, address res) = harness.parseValidationData(result);
        assertEq(res, aggregator, "Success + aggregator => adopt aggregator");
    }

    function test_intersectValidationData_WhenSameAggregator_ShouldKeepIt() public view {
        address aggregator = address(0xABCD);
        uint256 a = (uint256(10) << 208) | (uint256(100) << 160) | uint160(aggregator);
        uint256 b = (uint256(20) << 208) | (uint256(200) << 160) | uint160(aggregator);

        uint256 result = harness.intersectValidationData(a, b);
        (,, address res) = harness.parseValidationData(result);
        assertEq(res, aggregator, "Same aggregator => keep it");
    }

    function test_intersectValidationData_WhenDifferentAggregators_ShouldFail() public view {
        address agg1 = address(0xAAAA);
        address agg2 = address(0xBBBB);
        uint256 a = (uint256(10) << 208) | (uint256(100) << 160) | uint160(agg1);
        uint256 b = (uint256(20) << 208) | (uint256(200) << 160) | uint160(agg2);

        uint256 result = harness.intersectValidationData(a, b);
        (,, address res) = harness.parseValidationData(result);
        assertEq(res, address(1), "Different aggregators => conflict => fail");
    }

    function test_intersectValidationData_WhenAggregatorAndFailure_ShouldReturnFailure() public view {
        address aggregator = address(0xDEAD);
        uint256 a = (uint256(10) << 208) | (uint256(100) << 160) | uint160(aggregator);
        uint256 b = (uint256(20) << 208) | (uint256(200) << 160) | 1;

        uint256 result = harness.intersectValidationData(a, b);
        (,, address res) = harness.parseValidationData(result);
        assertEq(res, address(1), "Aggregator + failure => failure takes precedence");
    }

    // =========================================================================
    // intersectValidationData — ValidityFormatMismatch
    // =========================================================================

    function test_intersectValidationData_WhenFormatMismatch_ShouldRevert() public {
        // Block number format: both validAfter and validUntil have MODE_BIT (0x800000000000) set
        uint48 modeBit = 0x800000000000;

        // a uses block number format (both have MODE_BIT set)
        uint256 a = (uint256(modeBit | 10) << 208) | (uint256(modeBit | 100) << 160);
        // b uses timestamp format (no MODE_BIT)
        uint256 b = (uint256(20) << 208) | (uint256(200) << 160);

        vm.expectRevert(ValidityFormatMismatch.selector);
        harness.intersectValidationData(a, b);
    }

    function test_intersectValidationData_WhenBothBlockNumberFormat_ShouldSucceed() public view {
        uint48 modeBit = 0x800000000000;

        uint256 a = (uint256(modeBit | 10) << 208) | (uint256(modeBit | 100) << 160);
        uint256 b = (uint256(modeBit | 20) << 208) | (uint256(modeBit | 80) << 160);

        uint256 result = harness.intersectValidationData(a, b);
        (uint48 validAfter, uint48 validUntil,) = harness.parseValidationData(result);
        assertEq(validAfter, modeBit | 20, "validAfter should be max with MODE_BIT");
        assertEq(validUntil, modeBit | 80, "validUntil should be min with MODE_BIT");
    }

    function test_intersectValidationData_WhenTimestampFormatMismatchReversed_ShouldRevert() public {
        uint48 modeBit = 0x800000000000;

        // a uses timestamp format
        uint256 a = (uint256(10) << 208) | (uint256(100) << 160);
        // b uses block number format
        uint256 b = (uint256(modeBit | 20) << 208) | (uint256(modeBit | 200) << 160);

        vm.expectRevert(ValidityFormatMismatch.selector);
        harness.intersectValidationData(a, b);
    }
}
