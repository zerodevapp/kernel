// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TestExecutor {
    event TestExecutorDoNothing();

    function test() public {}

    function doNothing() external {
        // do nothing
        emit TestExecutorDoNothing();
    }
}
