pragma solidity ^0.8.0;

import {parseNonce} from "src/lib/Utils.sol";
import {Test} from "forge-std/Test.sol";
import {ValidationMode, ValidationType, ValidationId} from "src/types/Types.sol";
import {VALIDATION_TYPE_PERMISSION} from "src/types/Constants.sol";

contract UtilTest is Test {
    function testParseNonce(uint8 vMode, uint8 vType, uint160 vId, uint16 key, uint64 nonce) external {
        vm.assume(vType < 3); // 0 for root 1 for validator 2 for permission
        uint256 encodedNonce = uint256(vMode) << 248;
        encodedNonce += uint256(vType) << 240;
        encodedNonce += uint256(vId) << 80;
        encodedNonce += uint256(key) << 64;
        encodedNonce += uint256(nonce);
        (ValidationMode vM, ValidationType vT, ValidationId vI) = parseNonce(encodedNonce);
        assertEq(ValidationMode.unwrap(vM), bytes1(vMode));
        assertEq(ValidationType.unwrap(vT), bytes1(vType));
        if (vT == VALIDATION_TYPE_PERMISSION) {
            uint160 _vId = (vId >> 128) << 128;
            assertEq(ValidationId.unwrap(vI), bytes21(abi.encodePacked(vType, _vId, bytes16(0))));
        } else {
            assertEq(ValidationId.unwrap(vI), bytes21(abi.encodePacked(vType, vId)));
        }
    }
}
