// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";

import {Lib4337} from "src/lib/Lib4337.sol";

contract EntryPointV09ValidationHarness is EntryPoint {
    function getValidationData(uint256 validationData)
        external
        view
        returns (address aggregator, bool outOfValidityRange, bool isBlockRange)
    {
        return _getValidationData(validationData);
    }
}

contract CheckValidationDifferentialTest is Test {
    EntryPointV09ValidationHarness internal entryPoint;

    function setUp() public {
        entryPoint = new EntryPointV09ValidationHarness();
    }

    function testFuzz_CheckValidationMatchesEntryPointV09(
        uint48 validAfter,
        uint48 validUntil,
        uint160 aggregatorSeed,
        uint8 aggregatorMode,
        bool unbounded,
        uint64 currentBlock,
        uint64 currentTimestamp
    ) public {
        if (unbounded) validUntil = 0;

        address aggregator;
        if (aggregatorMode % 3 == 1) {
            aggregator = address(1);
        } else if (aggregatorMode % 3 == 2) {
            aggregator = address(aggregatorSeed | 2);
        }
        uint256 validationData = uint256(validAfter) << 208 | uint256(validUntil) << 160 | uint160(aggregator);

        vm.roll(currentBlock);
        vm.warp(currentTimestamp);

        (address entryPointAggregator, bool outOfValidityRange, bool isBlockRange) =
            entryPoint.getValidationData(validationData);

        // Lib4337.checkValidation is used only where signature aggregators are unsupported,
        // equivalent to EntryPoint validation with an expected aggregator of address(0).
        bool expected = entryPointAggregator == address(0) && !outOfValidityRange;
        assertEq(Lib4337.checkValidation(validationData), expected);

        (uint48 parsedValidAfter, uint48 parsedValidUntil,) = Lib4337.parseValidationData(validationData);
        assertEq(Lib4337._usesBlockNumberFormat(parsedValidAfter, parsedValidUntil), isBlockRange);
    }
}
