pragma solidity ^0.8.0;

import "./IPolicy.sol";

type PolicyConfig is bytes32;

// PolicyData is a 32 bytes array that contains the address of the policy
// [flags(12 bytes), address(20 bytes)]
// flags is 96 bits that contains the following information
// from last to first bit
// 1 bit : not for validatUserOp
// 1 bit : not for validateSignature
// 1 bit : not for validateCaller
library PolicyConfigLib {
    function pack(IPolicy addr, bytes12 flag) internal pure returns (PolicyConfig data) {
        assembly {
            data := or(addr, shl(160, flag))
        }
    }

    function getAddress(PolicyConfig data) internal pure returns (IPolicy policy) {
        assembly {
            policy := and(data, 0xffffffffffffffffffffffffffffffffffffffff)
        }
    }

    function getFlags(PolicyConfig data) internal pure returns (bytes12 flags) {
        assembly {
            flags := shr(160, data)
        }
    }

    function skipOnValidateUserOp(PolicyConfig data) internal pure returns (bool result) {
        assembly {
            let flags := shr(160, data)
            let mask := 0x1
            result := and(flags, mask)
        }
    }

    function skipOnValidateSignature(PolicyConfig data) internal pure returns (bool result) {
        assembly {
            let flags := shr(161, data)
            let mask := 0x1
            result := and(flags, mask)
        }
    }

    function skipOnValidateCaller(PolicyConfig data) internal pure returns (bool result) {
        assembly {
            let flags := shr(162, data)
            let mask := 0x1
            result := and(flags, mask)
        }
    }
}
