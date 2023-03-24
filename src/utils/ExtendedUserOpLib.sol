// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "account-abstraction/interfaces/UserOperation.sol";

library ExtendedUserOpLib {
    // small fix to handle userOp hash can be used for attack when offset location is not checked
    // info : https://github.com/eth-infinitism/account-abstraction/issues/237
    function checkUserOpOffset(UserOperation calldata userOp) internal pure returns (bool success) {
        bytes calldata sig = userOp.signature;
        bytes calldata cd = userOp.callData;
        bytes calldata initCode = userOp.initCode;
        bytes calldata paymasterAndData = userOp.paymasterAndData;
        assembly {
            if eq(add(initCode.offset, mul(div(add(initCode.length, 63), 32), 0x20)), cd.offset) { success := 1 }
            if and(eq(add(cd.offset, mul(div(add(cd.length, 63), 32), 0x20)), paymasterAndData.offset), success) {
                success := 1
            }
            if and(
                eq(add(paymasterAndData.offset, mul(div(add(paymasterAndData.length, 63), 32), 0x20)), sig.offset),
                success
            ) { success := 1 }
        }
    }
}
