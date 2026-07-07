// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IFallback} from "src/interfaces/IERC7579Modules.sol";

contract MockRevertingFallback is IFallback {
    error InstallFailed();

    function onInstall(bytes calldata) external payable {
        revert InstallFailed();
    }

    function onUninstall(bytes calldata) external payable {}

    function isModuleType(uint256 typeId) external pure returns (bool) {
        return typeId == 3;
    }

    function isInitialized(address) external pure returns (bool) {
        return false;
    }
}
