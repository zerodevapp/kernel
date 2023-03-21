// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@gnosis.pm/safe-contracts/contracts/common/Enum.sol";
interface IPolicy {
    function executeAndRevert(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation
    ) external view returns (bool);
}