// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "account-abstraction/interfaces/UserOperation.sol";

interface IPlugin {
    function validatePluginData(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        bytes calldata pluginDataAndSig
    )
        external
        returns (uint256 validationData, bytes32 dataHash);
}
