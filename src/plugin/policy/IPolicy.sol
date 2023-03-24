// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "src/utils/Exec.sol";

interface IPolicy {
    function executeAndRevert(address to, uint256 value, bytes calldata data, Operation operation)
        external
        view
        returns (bool);
}
