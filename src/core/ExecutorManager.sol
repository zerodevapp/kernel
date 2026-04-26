// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {
    EXECUTOR_MANAGER_STORAGE_SLOT,
    HOOK_MODULE_NOT_INSTALLED,
    HOOK_MODULE_INSTALLED_NO_HOOK
} from "../types/Constants.sol";
import {IExecutor, IHook} from "../interfaces/IERC7579Modules.sol";
import {ExecutorStorage, ExecutorConfig} from "../types/Structs.sol";
import {NotInstalled} from "../types/Error.sol";

/// @title ExecutorManager
/// @author taek <leekt216@gmail.com>
/// @notice Manages executor module installation and their associated hook configurations.
abstract contract ExecutorManager {
    function _hookEnabled(IHook _hook) internal view virtual returns (bool);

    /// @notice Returns the executor manager storage reference.
    function _executorStorage() internal pure returns (ExecutorStorage storage $) {
        assembly {
            $.slot := EXECUTOR_MANAGER_STORAGE_SLOT
        }
    }

    /// @notice Returns the hook configuration for a given executor.
    /// @param executor The executor module address.
    /// @return The ExecutorConfig containing the hook address.
    function executorConfig(address executor) external view returns (ExecutorConfig memory) {
        return _executorConfig(IExecutor(executor));
    }

    function _executorConfig(IExecutor executor) internal view returns (ExecutorConfig storage config) {
        config = _executorStorage().executorConfig[executor];
    }

    /// @notice Installs an executor module with an optional hook.
    /// @dev internalData format: first 20 bytes = hook address (address(0) means no hook, stored as address(1)).
    /// @param _executor The executor module address.
    /// @param _internalData Hook address (20 bytes); if empty, no hook is set.
    function _installExecutor(address _executor, bytes calldata _internalData, bool) internal {
        // NOTE: we don't care if install was successful
        address hook = _internalData.length >= 20 ? address(bytes20(_internalData[0:20])) : HOOK_MODULE_NOT_INSTALLED;
        if (hook == HOOK_MODULE_NOT_INSTALLED) {
            hook = HOOK_MODULE_INSTALLED_NO_HOOK; // address(1) indicates it is installed and does not require any hook
        } else {
            require(hook == HOOK_MODULE_INSTALLED_NO_HOOK || _hookEnabled(IHook(hook)), NotInstalled());
        }
        _executorConfig(IExecutor(_executor)).hook = IHook(hook);
    }

    /// @notice Uninstalls an executor module by zeroing its hook.
    /// @param _executor The executor module address.
    function _uninstallExecutor(address _executor, bytes calldata, bool) internal {
        _executorConfig(IExecutor(_executor)).hook = IHook(HOOK_MODULE_NOT_INSTALLED);
    }
}
