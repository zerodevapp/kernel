pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

import {parseNonce} from "src/lib/Utils.sol";
import {ValidationMode, ValidationType, ValidationId} from "src/types/Types.sol";
import {VALIDATION_TYPE_VALIDATOR, VALIDATION_TYPE_PERMISSION} from "src/types/Constants.sol";

/// @title ParseNonceHalmos
/// @notice Halmos proof that `parseNonce` faithfully decodes the documented nonce layout
///         `[vMode (1B) | vType (1B) | vIdPayload (20B) | nonceKey (2B) | seq (8B)]`.
///
///         Round-trip property: for any well-shaped `(vMode, vType, vId)` triple, encoding
///         it into a 32-byte nonce per the documented layout and then calling `parseNonce`
///         must yield the original triple, regardless of the symbolic `nonceKey` and `seq`
///         bytes occupying the low 10 bytes of the nonce.
///
///         A counterexample here would mean validation mis-routing (vId or vType pointing
///         at the wrong module) — a trivial-compromise class bug.
contract ParseNonceHalmos is SymTest, Test {
    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    /// @dev Pack the documented nonce layout for VALIDATION_TYPE_VALIDATOR.
    ///      Layout: [vMode | 0x01 | validator(20B) | nonceKey(2B) | seq(8B)].
    function _encodeValidatorNonce(bytes1 vMode, address validator, bytes2 nonceKey, bytes8 seq)
        internal
        pure
        returns (uint256 nonce)
    {
        nonce = (uint256(uint8(vMode)) << 248) | (uint256(0x01) << 240) | (uint256(uint160(validator)) << 80)
            | (uint256(uint16(nonceKey)) << 64) | uint256(uint64(seq));
    }

    /// @dev Pack the documented nonce layout for VALIDATION_TYPE_PERMISSION.
    ///      Layout: [vMode | 0x02 | pId(4B) | zeros(16B) | nonceKey(2B) | seq(8B)].
    ///      The 16 bytes between pId and nonceKey MUST be zero per the spec, otherwise
    ///      parseNonce silently drops them.
    function _encodePermissionNonce(bytes1 vMode, bytes4 pId, bytes2 nonceKey, bytes8 seq)
        internal
        pure
        returns (uint256 nonce)
    {
        nonce = (uint256(uint8(vMode)) << 248) | (uint256(0x02) << 240) | (uint256(uint32(pId)) << 208)
            | (uint256(uint16(nonceKey)) << 64) | uint256(uint64(seq));
    }

    // ---------------------------------------------------------------------
    // Property 1: VALIDATOR-typed nonces round-trip
    // ---------------------------------------------------------------------

    /// @notice For any (vMode, validator, nonceKey, seq), encoding as a
    ///         VALIDATOR-typed nonce and parsing must recover the same (vMode, 0x01,
    ///         [0x01 | validator]).
    function checkParseNonceRoundTripValidator() external {
        bytes1 vModeByte = bytes1(uint8(svm.createUint(8, "vModeByte")));
        address validator = svm.createAddress("validator");
        bytes2 nonceKey = bytes2(uint16(svm.createUint(16, "nonceKey")));
        bytes8 seq = bytes8(uint64(svm.createUint(64, "seq")));

        uint256 nonce = _encodeValidatorNonce(vModeByte, validator, nonceKey, seq);

        (ValidationMode vMode, ValidationType vType, ValidationId vId) = parseNonce(nonce);

        // vMode must be preserved exactly.
        assertEq(
            uint256(uint8(ValidationMode.unwrap(vMode))), uint256(uint8(vModeByte)), "vMode mismatch (validator branch)"
        );

        // vType must be VALIDATION_TYPE_VALIDATOR (0x01).
        assertEq(
            uint256(uint8(ValidationType.unwrap(vType))),
            uint256(uint8(ValidationType.unwrap(VALIDATION_TYPE_VALIDATOR))),
            "vType not VALIDATOR"
        );

        // vId must be [0x01 | validator (20 bytes)].
        bytes21 expectedVId;
        {
            uint168 packed = (uint168(0x01) << 160) | uint168(uint160(validator));
            expectedVId = bytes21(packed);
        }
        assertEq(bytes32(ValidationId.unwrap(vId)), bytes32(expectedVId), "vId mismatch (validator branch)");
    }

    // ---------------------------------------------------------------------
    // Property 2: PERMISSION-typed nonces round-trip
    // ---------------------------------------------------------------------

    /// @notice For any (vMode, pId, nonceKey, seq), encoding as a PERMISSION-typed
    ///         nonce and parsing must recover the same (vMode, 0x02, [0x02 | pId | 16 zeros]).
    function checkParseNonceRoundTripPermission() external {
        bytes1 vModeByte = bytes1(uint8(svm.createUint(8, "vModeByte")));
        bytes4 pId = bytes4(uint32(svm.createUint(32, "pId")));
        bytes2 nonceKey = bytes2(uint16(svm.createUint(16, "nonceKey")));
        bytes8 seq = bytes8(uint64(svm.createUint(64, "seq")));

        uint256 nonce = _encodePermissionNonce(vModeByte, pId, nonceKey, seq);

        (ValidationMode vMode, ValidationType vType, ValidationId vId) = parseNonce(nonce);

        // vMode must be preserved exactly.
        assertEq(
            uint256(uint8(ValidationMode.unwrap(vMode))),
            uint256(uint8(vModeByte)),
            "vMode mismatch (permission branch)"
        );

        // vType must be VALIDATION_TYPE_PERMISSION (0x02).
        assertEq(
            uint256(uint8(ValidationType.unwrap(vType))),
            uint256(uint8(ValidationType.unwrap(VALIDATION_TYPE_PERMISSION))),
            "vType not PERMISSION"
        );

        // vId must be [0x02 | pId (4 bytes) | 16 zero bytes].
        bytes21 expectedVId;
        {
            // High 5 bytes: [0x02, pId], low 16 bytes: zero.
            uint168 packed = (uint168(0x02) << 160) | (uint168(uint32(pId)) << 128);
            expectedVId = bytes21(packed);
        }
        assertEq(bytes32(ValidationId.unwrap(vId)), bytes32(expectedVId), "vId mismatch (permission branch)");
    }
}
