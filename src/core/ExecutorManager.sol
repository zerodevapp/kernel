// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {EXECUTOR_MANAGER_STORAGE_SLOT, SCOPED_EXECUTION_HOOK_NOT_INSTALLED} from "../types/Constants.sol";
import {IExecutor} from "../interfaces/IERC7579Modules.sol";
import {ExecutorStorage, ExecutorConfig} from "../types/Structs.sol";
import {InvalidDataLength, ScopedExecutionHookStillInstalled, ModuleNotInstalled} from "../types/Error.sol";

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

    /// @notice Installs an executor module.
    function _installExecutor(address _executor, bytes calldata _internalData, bool) internal {
        require(_internalData.length == 0, InvalidDataLength());
        // Executor installation intentionally does not depend on onInstall success (acknowledged in
        // TOB-KERNEL-11): executors may be EOAs or contracts that do not implement IModule, so the
        // lifecycle callbacks are best-effort for this module type. The trade-off: reinstalling a
        // STATEFUL executor whose onInstall reverts re-activates its previous state, so installers
        // of stateful executors must verify the onInstall effects themselves. Revocation is
        // unaffected: uninstall clears `installed` regardless of callback outcome.
        _executorConfig(IExecutor(_executor)).installed = true;
    }

    /// @notice Uninstalls an executor module.
    function _uninstallExecutor(address _executor, bytes calldata _internalData, bool) internal {
        require(_internalData.length == 0, InvalidDataLength());
        ExecutorConfig storage config = _executorConfig(IExecutor(_executor));
        // TOB-KERNEL-12: without this check, any installed module (e.g. the root validator) could
        // be routed through the executor uninstall path, firing its onUninstall under a wrong type.
        require(config.installed, ModuleNotInstalled());
        require(
            address(config.scopedExecutionHook) == SCOPED_EXECUTION_HOOK_NOT_INSTALLED,
            ScopedExecutionHookStillInstalled()
        );
        config.installed = false;
    }
}
