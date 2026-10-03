// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IScopedExecutionHook} from "src/interfaces/IERC7579Modules.sol";

contract MockRevertingHook is IScopedExecutionHook {
    error InstallFailed();

    function onInstall(bytes calldata) external payable {
        revert InstallFailed();
    }

    function onUninstall(bytes calldata) external payable {}

    function isModuleType(uint256 typeId) external pure returns (bool) {
        return typeId == 11;
    }

    function isInitialized(address) external pure returns (bool) {
        return false;
    }

    function preCheck(bytes32, address, uint256, bytes calldata) external payable returns (bytes memory) {
        return hex"";
    }

    function postCheck(bytes32, bytes calldata) external payable {}
}
