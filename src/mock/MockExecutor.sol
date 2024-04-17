// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IExecutor} from "../interfaces/IERC7579Modules.sol";
import {IERC7579Account, ExecMode} from "../interfaces/IERC7579Account.sol";

contract MockExecutor is IExecutor {
    mapping(address => bytes) public data;

    function onInstall(bytes calldata _data) external payable override {
        data[msg.sender] = _data;
    }

    function onUninstall(bytes calldata) external payable override {
        delete data[msg.sender];
    }

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == 2;
    }

    function isInitialized(address smartAccount) external view override returns (bool) {
        return data[smartAccount].length > 0;
    }

    function sudoDoExec(IERC7579Account account, ExecMode mode, bytes calldata executionCalldata) external payable {
        account.executeFromExecutor(mode, executionCalldata);
    }
}
