pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "src/utils/KernelHelper.sol";
import "src/common/Types.sol";

contract KernelHelperTest is Test {
    function testIntersect(
        ValidAfter validAfterA,
        ValidUntil validUntilA,
        ValidAfter validAfterB,
        ValidUntil validUntilB
    ) public {
        if (ValidUntil.unwrap(validUntilB) == 0) {
            validUntilB = ValidUntil.wrap(0xffffffffffff);
        }
        if (ValidUntil.unwrap(validUntilA) == 0) {
            validUntilA = ValidUntil.wrap(0xffffffffffff);
        }
        ValidationData a = packValidationData(validAfterA, validUntilA);
        ValidationData b = packValidationData(validAfterB, validUntilB);
        ValidationData c = _intersectValidationData(a, b);

        ValidationData expected = packValidationData(
            ValidAfter.unwrap(validAfterA) > ValidAfter.unwrap(validAfterB) ? validAfterA : validAfterB,
            ValidUntil.unwrap(validUntilA) < ValidUntil.unwrap(validUntilB) ? validUntilA : validUntilB
        );
        assertEq(ValidationData.unwrap(c), ValidationData.unwrap(expected));
    }
}
