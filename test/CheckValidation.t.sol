// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

import "src/lib/Lib4337.sol";

/// @dev RP-01: `Lib4337.checkValidation` must match canonical EntryPoint v0.9 semantics —
/// exact-zero success, block-number vs timestamp mode selection, and the exclusive
/// interval `(validAfter, validUntil]`.
contract CheckValidationTest is Test {
    uint48 constant MODE_BIT = 0x800000000000;

    function _pack(uint48 validAfter, uint48 validUntil, address res) internal pure returns (uint256) {
        return uint256(validAfter) << 208 | uint256(validUntil) << 160 | uint160(res);
    }

    // --- exact zero ---------------------------------------------------------

    function test_ExactZero_IsUnconditionalSuccess() public {
        // Even at block.timestamp == 0, canonical EntryPoint treats packed-zero as success.
        vm.warp(0);
        assertTrue(Lib4337.checkValidation(0));
    }

    // --- result field -------------------------------------------------------

    function test_NonzeroResult_Failure_IsInvalid() public {
        vm.warp(1000);
        assertFalse(Lib4337.checkValidation(_pack(100, 2000, address(1))));
    }

    function test_NonzeroResult_Aggregator_IsInvalid() public {
        vm.warp(1000);
        assertFalse(Lib4337.checkValidation(_pack(100, 2000, address(0x1234))));
    }

    // --- timestamp mode boundaries: valid iff current in (validAfter, validUntil] ---

    function test_Timestamp_CurrentEqualsValidAfter_IsInvalid() public {
        vm.warp(100);
        assertFalse(Lib4337.checkValidation(_pack(100, 200, address(0))));
    }

    function test_Timestamp_CurrentOneAboveValidAfter_IsValid() public {
        vm.warp(101);
        assertTrue(Lib4337.checkValidation(_pack(100, 200, address(0))));
    }

    function test_Timestamp_CurrentEqualsValidUntil_IsValid() public {
        vm.warp(200);
        assertTrue(Lib4337.checkValidation(_pack(100, 200, address(0))));
    }

    function test_Timestamp_CurrentOneAboveValidUntil_IsInvalid() public {
        vm.warp(201);
        assertFalse(Lib4337.checkValidation(_pack(100, 200, address(0))));
    }

    function test_Timestamp_ZeroValidUntil_IsUnbounded() public {
        // Raw validUntil == 0 normalizes to type(uint48).max (no expiry).
        vm.warp(uint256(type(uint48).max) - 1);
        assertTrue(Lib4337.checkValidation(_pack(100, 0, address(0))));
    }

    // --- block-number mode boundaries: compared against block.number ---------

    function test_Block_UsesBlockNumberNotTimestamp() public {
        // A deliberately incompatible timestamp proves block mode ignores block.timestamp.
        vm.warp(uint256(type(uint48).max) + 1);
        vm.roll(150);
        assertTrue(Lib4337.checkValidation(_pack(MODE_BIT | 100, MODE_BIT | 200, address(0))));
    }

    function test_Block_CurrentEqualsValidAfter_IsInvalid() public {
        vm.roll(100);
        assertFalse(Lib4337.checkValidation(_pack(MODE_BIT | 100, MODE_BIT | 200, address(0))));
    }

    function test_Block_CurrentOneAboveValidAfter_IsValid() public {
        vm.roll(101);
        assertTrue(Lib4337.checkValidation(_pack(MODE_BIT | 100, MODE_BIT | 200, address(0))));
    }

    function test_Block_CurrentEqualsValidUntil_IsValid() public {
        vm.roll(200);
        assertTrue(Lib4337.checkValidation(_pack(MODE_BIT | 100, MODE_BIT | 200, address(0))));
    }

    function test_Block_CurrentOneAboveValidUntil_IsInvalid() public {
        vm.roll(201);
        assertFalse(Lib4337.checkValidation(_pack(MODE_BIT | 100, MODE_BIT | 200, address(0))));
    }

    function test_Block_ZeroValidUntil_IsUnbounded() public {
        // MODE_BIT validAfter with raw zero validUntil stays block mode, unbounded upper.
        vm.roll(uint256(uint48(MODE_BIT | 100) & (MODE_BIT - 1)) + 1);
        assertTrue(Lib4337.checkValidation(_pack(MODE_BIT | 100, 0, address(0))));
    }

    // --- exact MODE_BIT classification (strictly greater than the flag) -------

    function test_ExactModeBitBound_ClassifiesAsTimestampMode() public pure {
        // EntryPoint v0.9 uses block-number mode only when both bounds exceed the flag.
        assertFalse(Lib4337._usesBlockNumberFormat(MODE_BIT, MODE_BIT));
        assertFalse(Lib4337._usesBlockNumberFormat(MODE_BIT, MODE_BIT | 10));
        // One bound below MODE_BIT → timestamp format.
        assertFalse(Lib4337._usesBlockNumberFormat(MODE_BIT - 1, MODE_BIT));
        assertFalse(Lib4337._usesBlockNumberFormat(MODE_BIT, MODE_BIT - 1));
    }
}
