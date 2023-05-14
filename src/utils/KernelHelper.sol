// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

function _intersectValidationData(uint256 a, uint256 b) pure returns (uint256 validationData) {
    require(uint160(a) == uint160(b), "account: different aggregator");
    uint48 validAfterA = uint48(a >> 160);
    uint48 validUntilA = uint48(a >> (48 + 160));
    uint48 validAfterB = uint48(b >> 160);
    uint48 validUntilB = uint48(b >> (48 + 160));

    if (validAfterA < validAfterB) validAfterA = validAfterB;
    if (validUntilA > validUntilB) validUntilA = validUntilB;
    validationData = uint256(uint160(a)) | (uint256(validAfterA) << 160) | (uint256(validUntilA) << (48 + 160));
}
