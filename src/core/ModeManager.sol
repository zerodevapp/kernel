pragma solidity ^0.8.0;

import {PackedUserOperation} from "../interfaces/PackedUserOperation.sol";

type SigMode is bytes2;

type SigData is bytes20;

type NonceKey is bytes2;

type PackedNonce is uint256;

library KernelNonceLib {
    function getMode(PackedNonce nonce) internal pure returns (SigMode mode) {
        assembly {
            mode := nonce
        }
    }

    function getData(PackedNonce nonce) internal pure returns (SigData data) {
        assembly {
            data := shl(16, nonce)
        }
    }

    function getKey(PackedNonce nonce) internal pure returns (NonceKey key) {
        assembly {
            key := shl(176, nonce)
        }
    }
}

contract ModeManager {
    error SigModeInvalid();
    // custom modes

    struct SigModeConfig {
        // maybe this is making things messy, let's comment out these until we figure out the usecases
        //uint48 validAfter;
        //uint48 validUntil;
        address validator;
    }

    mapping(SigMode mode => SigModeConfig) public modeConfig;

    function _checkMode(SigMode mode, SigData /*extraData*/ ) internal view {
        if (uint16(SigMode.unwrap(mode)) < 3) {
            return;
        } else if (modeConfig[mode].validator == address(0)) {
            revert SigModeInvalid();
        }
    }

    function _setMode(SigMode mode, address validator, bytes calldata _data) internal {}
}
