// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {Lib4337Harness} from "../mock/Lib4337Harness.sol";
import {ValidityFormatMismatch} from "src/types/Error.sol";

abstract contract Lib4337_Test is Test {
    Lib4337Harness harness;

    // State variables for BTT branch tracking - set by modifiers, used by tests
    uint256 internal _preValidationData;
    uint256 internal _validationRes;
    uint256 internal _currentTimestamp;

    /// @dev MODE_BIT from Lib4337 - highest bit of uint48
    uint48 internal constant MODE_BIT = 0x800000000000;

    function setUp() public virtual {
        harness = new Lib4337Harness();
    }

    // Helper to pack validation data: validAfter (48 bits) | validUntil (48 bits) | result (160 bits)
    function packValidationData(uint48 validAfter, uint48 validUntil, address result) internal pure returns (uint256) {
        return (uint256(validAfter) << 208) | (uint256(validUntil) << 160) | uint160(result);
    }

    /*//////////////////////////////////////////////////////////////
                    parseValidationData TESTS
    //////////////////////////////////////////////////////////////*/

    modifier whenCallingParseValidationData() {
        _preValidationData = packValidationData(100, 0, address(0));
        _;
    }

    function test_GivenValidUntilIsZeroInThePackedData() external whenCallingParseValidationData {
        // Pack data with validUntil = 0
        uint256 validationData = packValidationData(100, 0, address(0));

        (uint48 validAfter, uint48 validUntil, address result) = harness.parseValidationData(validationData);

        assertEq(validAfter, 100, "validAfter should be 100");
        assertEq(validUntil, type(uint48).max, "validUntil should be max uint48 when packed as 0");
        assertEq(result, address(0), "result should be address(0)");
    }

    function test_GivenValidUntilIsNon_zeroInThePackedData() external whenCallingParseValidationData {
        // Pack data with validUntil = 5000
        uint256 validationData = packValidationData(100, 5000, address(0x1234));

        (uint48 validAfter, uint48 validUntil, address result) = harness.parseValidationData(validationData);

        assertEq(validAfter, 100, "validAfter should be 100");
        assertEq(validUntil, 5000, "validUntil should be exact value 5000");
        assertEq(result, address(0x1234), "result should be 0x1234");
    }

    function test_GivenValidAfterIsZeroInThePackedData() external whenCallingParseValidationData {
        // Pack data with validAfter = 0
        uint256 validationData = packValidationData(0, 5000, address(0));

        (uint48 validAfter, uint48 validUntil, address result) = harness.parseValidationData(validationData);

        assertEq(validAfter, 0, "validAfter should be 0");
        assertEq(validUntil, 5000, "validUntil should be 5000");
        assertEq(result, address(0), "result should be address(0)");
    }

    function test_GivenResultIsANon_zeroAddress() external whenCallingParseValidationData {
        address aggregator = address(0xdeadbeefdeadbeefdeadbeef);
        uint256 validationData = packValidationData(50, 1000, aggregator);

        (uint48 validAfter, uint48 validUntil, address result) = harness.parseValidationData(validationData);

        assertEq(validAfter, 50, "validAfter should be 50");
        assertEq(validUntil, 1000, "validUntil should be 1000");
        assertEq(result, aggregator, "result should be the aggregator address");
    }

    /*//////////////////////////////////////////////////////////////
                    checkValidation TESTS
    //////////////////////////////////////////////////////////////*/

    modifier whenCallingCheckValidation() {
        _currentTimestamp = 1000;
        vm.warp(_currentTimestamp);
        _;
    }

    function test_GivenValidAfterIsGreaterThanCurrentTimestamp() external whenCallingCheckValidation {
        uint256 validationData = packValidationData(2000, 0, address(0));

        bool isValid = harness.checkValidation(validationData);

        assertFalse(isValid, "should return false when validAfter is in the future");
    }

    function test_GivenValidUntilIsLessThanCurrentTimestamp() external whenCallingCheckValidation {
        vm.warp(5000);
        uint256 validationData = packValidationData(0, 1000, address(0));

        bool isValid = harness.checkValidation(validationData);

        assertFalse(isValid, "should return false when validUntil is in the past");
    }

    function test_GivenResultAddressIsNotZero() external whenCallingCheckValidation {
        uint256 validationData = packValidationData(0, 0, address(1));

        bool isValid = harness.checkValidation(validationData);

        assertFalse(isValid, "should return false when result is not address(0)");
    }

    function test_GivenTimeBoundsAreValidAndResultIsZero() external whenCallingCheckValidation {
        uint256 validationData = packValidationData(500, 2000, address(0));

        bool isValid = harness.checkValidation(validationData);

        assertTrue(isValid, "should return true when time bounds are valid and result is zero");
    }

    function test_GivenValidationDataIsZero() external whenCallingCheckValidation {
        // validationData = 0 means: validAfter=0, validUntil=0 (becomes max), result=address(0) => true
        bool isValid = harness.checkValidation(0);

        assertTrue(isValid, "should return true when validation data is zero (all defaults)");
    }

    function test_GivenValidAfterEqualsCurrentTimestamp() external whenCallingCheckValidation {
        // Canonical EntryPoint v0.9: validAfter is exclusive, so current == validAfter is NOT yet valid.
        uint256 validationData = packValidationData(uint48(_currentTimestamp), 0, address(0));

        bool isValid = harness.checkValidation(validationData);

        assertFalse(isValid, "should return false when validAfter equals current timestamp");
    }

    /*//////////////////////////////////////////////////////////////
                    intersectValidationData TESTS
    //////////////////////////////////////////////////////////////*/

    modifier whenCallingIntersectValidationData() {
        _preValidationData = packValidationData(100, 200, address(0x1234));
        _validationRes = packValidationData(100, 200, address(0x5678));
        _;
    }

    function test_GivenPreValidationDataIsZero() external whenCallingIntersectValidationData {
        _preValidationData = 0;

        uint256 result = harness.intersectValidationData(_preValidationData, _validationRes);

        assertEq(result, _validationRes, "should return validationRes via short circuit when preValidationData is 0");
    }

    function test_GivenValidationResIsZero() external whenCallingIntersectValidationData {
        _validationRes = 0;

        uint256 result = harness.intersectValidationData(_preValidationData, _validationRes);

        assertEq(
            result, _preValidationData, "should return preValidationData via short circuit when validationRes is 0"
        );
    }

    modifier givenBothValuesAreNon_zero() {
        if (_preValidationData == 0) {
            _preValidationData = packValidationData(100, 1000, address(0x1));
        }
        if (_validationRes == 0) {
            _validationRes = packValidationData(100, 1000, address(0x2));
        }
        _;
    }

    function test_GivenValidUntil1IsZero() external whenCallingIntersectValidationData givenBothValuesAreNon_zero {
        uint256 preValidationData = packValidationData(100, 0, address(0x1));
        uint256 validationRes = packValidationData(100, 1000, address(0x2));

        uint256 result = harness.intersectValidationData(preValidationData, validationRes);

        uint48 resultValidUntil = uint48(result >> 160);
        assertEq(resultValidUntil, 1000, "should use validUntil2 since validUntil1 (max) > validUntil2");
    }

    function test_GivenValidUntil2IsZero() external whenCallingIntersectValidationData givenBothValuesAreNon_zero {
        uint256 preValidationData = packValidationData(100, 1000, address(0x1));
        uint256 validationRes = packValidationData(100, 0, address(0x2));

        uint256 result = harness.intersectValidationData(preValidationData, validationRes);

        uint48 resultValidUntil = uint48(result >> 160);
        assertEq(resultValidUntil, 1000, "should use validUntil1 since validUntil2 is max");
    }

    function test_GivenValidUntil1IsGreaterThanValidUntil2()
        external
        whenCallingIntersectValidationData
        givenBothValuesAreNon_zero
    {
        uint256 preValidationData = packValidationData(100, 2000, address(0x1));
        uint256 validationRes = packValidationData(100, 1000, address(0x2));

        uint256 result = harness.intersectValidationData(preValidationData, validationRes);

        uint48 resultValidUntil = uint48(result >> 160);
        assertEq(resultValidUntil, 1000, "should use validUntil2 (smaller value)");
    }

    function test_GivenValidUntil1IsLessThanOrEqualToValidUntil2()
        external
        whenCallingIntersectValidationData
        givenBothValuesAreNon_zero
    {
        uint256 preValidationData = packValidationData(100, 1000, address(0x1));
        uint256 validationRes = packValidationData(100, 2000, address(0x2));

        uint256 result = harness.intersectValidationData(preValidationData, validationRes);

        uint48 resultValidUntil = uint48(result >> 160);
        assertEq(resultValidUntil, 1000, "should use validUntil1 (smaller value)");
    }

    function test_GivenValidAfter1IsLessThanValidAfter2()
        external
        whenCallingIntersectValidationData
        givenBothValuesAreNon_zero
    {
        uint256 preValidationData = packValidationData(100, 1000, address(0x1));
        uint256 validationRes = packValidationData(200, 1000, address(0x2));

        uint256 result = harness.intersectValidationData(preValidationData, validationRes);

        uint48 resultValidAfter = uint48(result >> 208);
        assertEq(resultValidAfter, 200, "should use validAfter2 (larger value)");
    }

    function test_GivenValidAfter1IsGreaterThanOrEqualToValidAfter2()
        external
        whenCallingIntersectValidationData
        givenBothValuesAreNon_zero
    {
        uint256 preValidationData = packValidationData(300, 1000, address(0x1));
        uint256 validationRes = packValidationData(200, 1000, address(0x2));

        uint256 result = harness.intersectValidationData(preValidationData, validationRes);

        uint48 resultValidAfter = uint48(result >> 208);
        assertEq(resultValidAfter, 300, "should use validAfter1 (larger value)");
    }

    function test_GivenEitherResultIs1() external whenCallingIntersectValidationData givenBothValuesAreNon_zero {
        // preValidationData result = 1 (failure)
        uint256 preValidationData = packValidationData(100, 1000, address(1));
        uint256 validationRes = packValidationData(100, 1000, address(0x5678));
        address resultAddr = address(uint160(harness.intersectValidationData(preValidationData, validationRes)));
        assertEq(resultAddr, address(1), "should return 1 when preValidationData is failure");

        // validationRes result = 1 (failure)
        preValidationData = packValidationData(100, 1000, address(0x1234));
        validationRes = packValidationData(100, 1000, address(1));
        resultAddr = address(uint160(harness.intersectValidationData(preValidationData, validationRes)));
        assertEq(resultAddr, address(1), "should return 1 when validationRes is failure");
    }

    function test_GivenBothResultsAre0() external whenCallingIntersectValidationData givenBothValuesAreNon_zero {
        uint256 preValidationData = packValidationData(100, 1000, address(0));
        uint256 validationRes = packValidationData(100, 1000, address(0));

        address resultAddr = address(uint160(harness.intersectValidationData(preValidationData, validationRes)));
        assertEq(resultAddr, address(0), "should return 0 when both succeed");
    }

    function test_GivenPreValidationDataHasAggregatorAndValidationResIsSuccess()
        external
        whenCallingIntersectValidationData
        givenBothValuesAreNon_zero
    {
        uint256 preValidationData = packValidationData(100, 1000, address(0x1234));
        uint256 validationRes = packValidationData(100, 1000, address(0));

        address resultAddr = address(uint160(harness.intersectValidationData(preValidationData, validationRes)));
        assertEq(resultAddr, address(0x1234), "should preserve preValidationData aggregator");
    }

    function test_GivenPreValidationDataIsSuccessAndValidationResHasAggregator()
        external
        whenCallingIntersectValidationData
        givenBothValuesAreNon_zero
    {
        uint256 preValidationData = packValidationData(100, 1000, address(0));
        uint256 validationRes = packValidationData(100, 1000, address(0x5678));

        address resultAddr = address(uint160(harness.intersectValidationData(preValidationData, validationRes)));
        assertEq(resultAddr, address(0x5678), "should adopt validationRes aggregator");
    }

    function test_GivenBothHaveTheSameAggregator()
        external
        whenCallingIntersectValidationData
        givenBothValuesAreNon_zero
    {
        uint256 preValidationData = packValidationData(100, 1000, address(0xABCD));
        uint256 validationRes = packValidationData(100, 1000, address(0xABCD));

        address resultAddr = address(uint160(harness.intersectValidationData(preValidationData, validationRes)));
        assertEq(resultAddr, address(0xABCD), "should return the shared aggregator");
    }

    function test_GivenBothHaveDifferentAggregators()
        external
        whenCallingIntersectValidationData
        givenBothValuesAreNon_zero
    {
        uint256 preValidationData = packValidationData(100, 1000, address(0x1234));
        uint256 validationRes = packValidationData(100, 1000, address(0x5678));

        address resultAddr = address(uint160(harness.intersectValidationData(preValidationData, validationRes)));
        assertEq(resultAddr, address(1), "should return 1 (conflict) when aggregators differ");
    }

    /*//////////////////////////////////////////////////////////////
            VALIDITY FORMAT MISMATCH TESTS (block number vs timestamp)
    //////////////////////////////////////////////////////////////*/

    function test_GivenPreValidationDataUsesBlockNumberFormatAndValidationResUsesTimestampFormat()
        external
        whenCallingIntersectValidationData
        givenBothValuesAreNon_zero
    {
        // preValidationData: both validAfter and validUntil have MODE_BIT set (block number format)
        // validationRes: neither has MODE_BIT set (timestamp format)
        uint48 blockAfter = MODE_BIT | 100;
        uint48 blockUntil = MODE_BIT | 2000;
        uint256 preValidationData = packValidationData(blockAfter, blockUntil, address(0));
        uint256 validationRes = packValidationData(100, 2000, address(0));

        vm.expectRevert(ValidityFormatMismatch.selector);
        harness.intersectValidationData(preValidationData, validationRes);
    }

    function test_GivenPreValidationDataUsesTimestampFormatAndValidationResUsesBlockNumberFormat()
        external
        whenCallingIntersectValidationData
        givenBothValuesAreNon_zero
    {
        // preValidationData: timestamp format
        // validationRes: block number format
        uint48 blockAfter = MODE_BIT | 100;
        uint48 blockUntil = MODE_BIT | 2000;
        uint256 preValidationData = packValidationData(100, 2000, address(0));
        uint256 validationRes = packValidationData(blockAfter, blockUntil, address(0));

        vm.expectRevert(ValidityFormatMismatch.selector);
        harness.intersectValidationData(preValidationData, validationRes);
    }

    function test_GivenBothUseBlockNumberFormat()
        external
        whenCallingIntersectValidationData
        givenBothValuesAreNon_zero
    {
        // Both use block number format - should not revert
        uint48 blockAfter1 = MODE_BIT | 100;
        uint48 blockUntil1 = MODE_BIT | 2000;
        uint48 blockAfter2 = MODE_BIT | 200;
        uint48 blockUntil2 = MODE_BIT | 1500;
        uint256 preValidationData = packValidationData(blockAfter1, blockUntil1, address(0));
        uint256 validationRes = packValidationData(blockAfter2, blockUntil2, address(0));

        uint256 result = harness.intersectValidationData(preValidationData, validationRes);

        // Should take max(validAfter) and min(validUntil)
        uint48 resultValidAfter = uint48(result >> 208);
        uint48 resultValidUntil = uint48(result >> 160);
        assertEq(resultValidAfter, blockAfter2, "should use larger validAfter (blockAfter2)");
        assertEq(resultValidUntil, blockUntil2, "should use smaller validUntil (blockUntil2)");
    }

    /*//////////////////////////////////////////////////////////////
                    BOTH ZERO TEST
    //////////////////////////////////////////////////////////////*/

    function test_GivenBothValuesAreZero() external whenCallingIntersectValidationData {
        // Both zero means both short-circuit: 0 | 0 = 0
        uint256 result = harness.intersectValidationData(0, 0);
        assertEq(result, 0, "should return zero when both are zero");
    }

    /*//////////////////////////////////////////////////////////////
                    usesBlockNumberFormat TESTS
    //////////////////////////////////////////////////////////////*/

    modifier whenCallingUsesBlockNumberFormat() {
        _;
    }

    function test_GivenBothValidAfterAndValidUntilHaveMODE_BITSet() external whenCallingUsesBlockNumberFormat {
        // Both have MODE_BIT set => block number format
        uint48 validAfter = MODE_BIT | 100;
        uint48 validUntil = MODE_BIT | 2000;

        bool result = harness.usesBlockNumberFormat(validAfter, validUntil);
        assertTrue(result, "should return true when both have MODE_BIT");
    }

    function test_GivenOnlyValidAfterHasMODE_BITSet() external whenCallingUsesBlockNumberFormat {
        uint48 validAfter = MODE_BIT | 100;
        uint48 validUntil = 2000; // no MODE_BIT

        bool result = harness.usesBlockNumberFormat(validAfter, validUntil);
        assertFalse(result, "should return false when only validAfter has MODE_BIT");
    }

    function test_GivenOnlyValidUntilHasMODE_BITSet() external whenCallingUsesBlockNumberFormat {
        uint48 validAfter = 100; // no MODE_BIT
        uint48 validUntil = MODE_BIT | 2000;

        bool result = harness.usesBlockNumberFormat(validAfter, validUntil);
        assertFalse(result, "should return false when only validUntil has MODE_BIT");
    }

    function test_GivenNeitherHasMODE_BITSet() external whenCallingUsesBlockNumberFormat {
        uint48 validAfter = 100;
        uint48 validUntil = 2000;

        bool result = harness.usesBlockNumberFormat(validAfter, validUntil);
        assertFalse(result, "should return false when neither has MODE_BIT");
    }
}

contract Lib4337_Concrete_Test is Lib4337_Test {}
