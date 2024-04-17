// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

struct Execution {
    address target;
    uint256 value;
    bytes callData;
}
