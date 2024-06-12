// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {IHook, IExecutor} from "../interfaces/IERC7579Modules.sol";
import {IERC7579Account} from "../interfaces/IERC7579Account.sol";
import {ModuleLib} from "../utils/ModuleLib.sol";
import {EXECUTOR_MANAGER_STORAGE_SLOT, MODULE_TYPE_EXECUTOR} from "../types/Constants.sol";

abstract contract ExecutorManager {
    struct ExecutorConfig {
        IHook hook; // address(1) : hook not required, address(0) : validator not installed
    }

    struct ExecutorStorage {
        mapping(IExecutor => ExecutorConfig) executorConfig;
    }

    function executorConfig(IExecutor executor) external view returns (ExecutorConfig memory) {
        return _executorConfig(executor);
    }

    function _executorConfig(IExecutor executor) internal view returns (ExecutorConfig storage config) {
        ExecutorStorage storage es;
        bytes32 slot = EXECUTOR_MANAGER_STORAGE_SLOT;
        assembly {
            es.slot := slot
        }
        config = es.executorConfig[executor];
    }

    function _installExecutor(IExecutor executor, bytes calldata executorData, IHook hook) internal {
        _installExecutorWithoutInit(executor, hook);
        executor.onInstall(executorData);
    }

    function _installExecutorWithoutInit(IExecutor executor, IHook hook) internal {
        if (address(hook) == address(0)) {
            hook = IHook(address(1));
        }
        ExecutorConfig storage config = _executorConfig(executor);
        config.hook = hook;
        emit IERC7579Account.ModuleInstalled(MODULE_TYPE_EXECUTOR, address(executor));
    }

    function _uninstallExecutor(IExecutor executor, bytes calldata executorData) internal returns (IHook hook) {
        ExecutorConfig storage config = _executorConfig(executor);
        hook = config.hook;
        config.hook = IHook(address(0));
        ModuleLib.uninstallModule(address(executor), executorData);
        emit IERC7579Account.ModuleUninstalled(MODULE_TYPE_EXECUTOR, address(executor));
    }
}
