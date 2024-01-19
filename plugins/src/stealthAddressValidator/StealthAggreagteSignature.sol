// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {EllipticCurve} from "./EllipticCurve.sol";

library StealthAggreagteSignature {
    uint256 public constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 public constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
    uint256 public constant AA = 0;
    uint256 public constant BB = 7;
    uint256 public constant PP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 public constant N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;

    function validateAggregatedSignature(
        uint256 _pubkey,
        uint256 _dhkey,
        uint8 _pubkeyPrefix,
        uint8 _dhkeyPrefix,
        bytes32 _message,
        bytes calldata _signature
    ) external pure returns (bool) {
        uint256 aggh2;
        uint256 aggpb;
        uint256 aggdh;

        uint256 sigr = uint256(bytes32(_signature[0:32]));
        uint256 sigs = uint256(bytes32(_signature[32:64]));
        uint256 sinv = EllipticCurve.invMod(sigs, N);
        uint256 num_message = uint256(_message);

        assembly {
            aggh2 := mulmod(mulmod(sinv, num_message, N), num_message, N)
            aggpb := mulmod(mulmod(sinv, sigr, N), num_message, N)
            aggdh := mulmod(mulmod(sinv, sigr, N), sigr, N)
        }
        (uint256 p1x, uint256 p1y) = EllipticCurve.ecMul(aggh2, GX, GY, AA, PP);
        uint256 pubY = EllipticCurve.deriveY(_pubkeyPrefix, _pubkey, AA, BB, PP);
        uint256 pubdhY = EllipticCurve.deriveY(_dhkeyPrefix, _dhkey, AA, BB, PP);

        (uint256 p2x, uint256 p2y) = EllipticCurve.ecMul(aggpb, _pubkey, pubY, AA, PP);
        (uint256 p3x, uint256 p3y) = EllipticCurve.ecMul(aggdh, _dhkey, pubdhY, AA, PP);
        (uint256 aggp1x, uint256 aggp1y) = EllipticCurve.ecAdd(p1x, p1y, p2x, p2y, AA, PP);
        (uint256 aggpx,) = EllipticCurve.ecAdd(aggp1x, aggp1y, p3x, p3y, AA, PP);

        return aggpx % N == sigr;
    }
}
