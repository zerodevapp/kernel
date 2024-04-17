// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract TestCounter {
    uint256 public counter;

    function test_ignore() public {}

    function increment() public {
        counter += 1;
    }
}
