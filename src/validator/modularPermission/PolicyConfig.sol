pragma solidity ^0.8.0;

import "./IPolicy.sol";

type PolicyConfig is bytes32;

function toFlag(uint256 x) pure returns (bytes12) {
    return bytes12(bytes32(x << 160));
}

function toPermissionFlag(uint256 x) pure returns (bytes12) {
    bytes12 ret = bytes12(bytes32(x << 160));
    assembly {
        ret := not(ret)
    }
    return ret;
}

bytes12 constant MAX_FLAG = 0xffffffffffffffffffffffff;
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
            data := or(addr, flag)
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
            result := and(flags, 0x1)
        }
    }

    function skipOnValidateSignature(PolicyConfig data) internal pure returns (bool result) {
        assembly {
            let flags := shr(161, data)
            result := and(flags, 0x1)
        }
    }

    function skipOnValidateCaller(PolicyConfig data) internal pure returns (bool result) {
        assembly {
            let flags := shr(162, data)
            result := and(flags, 0x1)
        }
    }
}
