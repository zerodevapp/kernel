// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "./IPolicy.sol";

contract SudoPolicy is IPolicy {
    function executeAndRevert(
        address ,
        uint256 ,
        bytes calldata ,
        Enum.Operation 
    ) external pure override returns (bool) {
        return true;
    }
}