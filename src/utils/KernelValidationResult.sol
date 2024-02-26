// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {SIG_VALIDATION_FAILED_UINT} from "../types/Constants.sol";
import {ValidationData, getValidationResult} from "../types/Types.sol";

function _intersectValidationData(ValidationData a, ValidationData b) pure returns (ValidationData validationData) {
    // a == 2 , b == 0 => 0
    // a == 2 , b == 2 => 2
    // a == 0 , b == 2 => 0
    // a != 0 , b != 0 => 1
    // a != 0 , b == 0 => a
    // a == 0 , b != 0 => b
    assembly {
        // xor(a,b) == shows only matching bits
        // and(xor(a,b), 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff) == filters out the validAfter and validUntil bits
        // if the result is not zero, then aggregator part is not matching
        // validCase :
        // a == 0 || b == 0 || xor(a,b) == 0
        // invalidCase :
        // a mul b != 0 && xor(a,b) != 0
        let sum := shl(96, add(a, b))
        switch or(
            iszero(and(xor(a, b), 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff)),
            or(eq(sum, shl(96, a)), eq(sum, shl(96, b)))
        )
        case 1 {
            validationData := and(or(a, b), 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff)
            // validAfter
            let a_vd := and(0xffffffffffff0000000000000000000000000000000000000000000000000000, a)
            let b_vd := and(0xffffffffffff0000000000000000000000000000000000000000000000000000, b)
            validationData := or(validationData, xor(a_vd, mul(xor(a_vd, b_vd), gt(b_vd, a_vd))))
            // validUntil
            a_vd := and(0x000000000000ffffffffffff0000000000000000000000000000000000000000, a)
            if iszero(a_vd) { a_vd := 0x000000000000ffffffffffff0000000000000000000000000000000000000000 }
            b_vd := and(0x000000000000ffffffffffff0000000000000000000000000000000000000000, b)
            if iszero(b_vd) { b_vd := 0x000000000000ffffffffffff0000000000000000000000000000000000000000 }
            let until := xor(a_vd, mul(xor(a_vd, b_vd), lt(b_vd, a_vd)))
            if iszero(until) { until := 0x000000000000ffffffffffff0000000000000000000000000000000000000000 }
            validationData := or(validationData, until)
        }
        default { validationData := SIG_VALIDATION_FAILED_UINT }
    }
}
