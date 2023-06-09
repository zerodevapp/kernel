// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

uint256 constant SIG_VALIDATION_FAILED = 1;

function _intersectValidationData(uint256 a, uint256 b) pure returns (uint256 validationData) {
    if (uint160(a) != uint160(b)) {
        return SIG_VALIDATION_FAILED;
    }
    uint48 validAfterA = uint48(a >> (160 + 48));
    uint48 validUntilA = uint48(a >> 160);
    if(validUntilA == 0) {
        validUntilA = type(uint48).max;
    }
    uint48 validAfterB = uint48(b >> (160 + 48));
    uint48 validUntilB = uint48(b >> 160);
    if(validUntilB == 0) {
        validUntilB = type(uint48).max;
    }

    if (validAfterA < validAfterB) validAfterA = validAfterB;
    if (validUntilA > validUntilB) validUntilA = validUntilB;
    validationData = uint256(uint160(a)) | (uint256(validUntilA) << 160) | (uint256(validAfterA) << (48 + 160));
}
