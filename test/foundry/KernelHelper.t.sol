pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "src/utils/KernelHelper.sol";
import "account-abstraction/core/Helpers.sol";

contract KernelHelperTest is Test {
    function testIntersect(uint48 validAfterA, uint48 validUntilA, uint48 validAfterB, uint48 validUntilB) public {
        if (validUntilB == 0) {
            validUntilB = 0xffffffffffff;
        }
        if (validUntilA == 0) {
            validUntilA = 0xffffffffffff;
        }
        uint256 a = _packValidationData(false, validUntilA, validAfterA);
        uint256 b = _packValidationData(false, validUntilB, validAfterB);
        uint256 c = _intersectValidationData(a, b);

        uint256 expected = _packValidationData(
            false,
            validUntilA < validUntilB ? validUntilA : validUntilB,
            validAfterA > validAfterB ? validAfterA : validAfterB
        );
        assertEq(c, expected);
    }

    function testIntersectDiff(address a, address b) public {
        uint256 a_packed = _packValidationData(ValidationData({
            aggregator : a,
            validAfter : 0,
            validUntil : 0
        }));
        uint256 b_packed = _packValidationData(ValidationData({
            aggregator : b,
            validAfter : 0,
            validUntil : 0
        }));
        uint256 c = _intersectValidationData(a_packed, b_packed);
        assertEq(c, 1);
    }
}
