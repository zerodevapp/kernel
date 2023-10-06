// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {SIG_VALIDATION_FAILED_UINT} from "../common/Constants.sol";
import {ValidationData} from "../common/Types.sol";

function _intersectValidationData(ValidationData a, ValidationData b) pure returns (ValidationData validationData) {
    assembly {
        // xor(a,b) == shows only matching bits
        // and(xor(a,b), 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff) == filters out the validAfter and validUntil bits
        // if the result is not zero, then aggregator part is not matching
        switch iszero(and(xor(a, b), 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff))
        case 1 {
            // validAfter
            let a_vd := and(0xffffffffffff000000000000ffffffffffffffffffffffffffffffffffffffff, a)
            let b_vd := and(0xffffffffffff000000000000ffffffffffffffffffffffffffffffffffffffff, b)
            validationData := xor(a_vd, mul(xor(a_vd, b_vd), gt(b_vd, a_vd)))
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
