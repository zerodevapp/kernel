// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Lib4337} from "src/lib/Lib4337.sol";

contract Lib4337Harness {
    function parseValidationData(uint256 validationData)
        external
        pure
        returns (uint48 validAfter, uint48 validUntil, address result)
    {
        return Lib4337.parseValidationData(validationData);
    }

    function checkValidation(uint256 validationData) external view returns (bool) {
        return Lib4337.checkValidation(validationData);
    }

    function intersectValidationData(uint256 a, uint256 b) external pure returns (uint256) {
        return Lib4337.intersectValidationData(a, b);
    }

    function usesBlockNumberFormat(uint48 validAfter, uint48 validUntil) external pure returns (bool) {
        return Lib4337._usesBlockNumberFormat(validAfter, validUntil);
    }
}
