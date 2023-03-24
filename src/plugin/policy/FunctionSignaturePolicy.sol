// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./IPolicy.sol";
import "openzeppelin-contracts/contracts/utils/Create2.sol";

struct Policy {
    address to;
    bytes4 sig;
}

contract FunctionSignaturePolicy is IPolicy {
    mapping(address => mapping(bytes4 => bool)) public policies;

    constructor(Policy[] memory _policies) {
        for (uint256 i = 0; i < _policies.length; i++) {
            policies[_policies[i].to][_policies[i].sig] = true;
        }
    }

    // we are not going to allow Delegation call and value > 0
    function executeAndRevert(address to, uint256 value, bytes calldata data, Operation)
        external
        view
        override
        returns (bool)
    {
        if (value > 0) {
            return false;
        }
        bytes4 selector = bytes4(data[0:4]);
        return policies[to][selector];
    }
}
