// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {EXECUTOR_MANAGER_STORAGE_SLOT} from "../types/Constants.sol";
import {IExecutor} from "../interfaces/IERC7579Modules.sol";
import {ExecutorStorage, ExecutorConfig} from "../types/Structs.sol";
import {InvalidDataLength} from "../types/Error.sol";

/// @title ExecutorManager
/// @author taek <leekt216@gmail.com>
/// @notice Manages executor module installation state.
abstract contract ExecutorManager {
    /// @notice Returns the executor manager storage reference.
    function _executorStorage() internal pure returns (ExecutorStorage storage $) {
        assembly {
            $.slot := EXECUTOR_MANAGER_STORAGE_SLOT
        }
    }

    /// @notice Returns the configuration for a given executor.
    function executorConfig(address executor) external view returns (ExecutorConfig memory) {
        return _executorConfig(IExecutor(executor));
    }

    function _executorConfig(IExecutor executor) internal view returns (ExecutorConfig storage config) {
        config = _executorStorage().executorConfig[executor];
    }

    /// @notice Installs an executor module without a hook.
    function _installExecutor(address _executor, bytes calldata _internalData, bool) internal {
        require(_internalData.length == 0, InvalidDataLength());
        // Executor installation intentionally does not depend on onInstall success.
        _executorConfig(IExecutor(_executor)).installed = true;
    }

    /// @notice Uninstalls an executor module.
    function _uninstallExecutor(address _executor, bytes calldata _internalData, bool) internal {
        require(_internalData.length == 0, InvalidDataLength());
        _executorConfig(IExecutor(_executor)).installed = false;
    }
}
