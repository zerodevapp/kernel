pragma solidity ^0.8.0;

import {IHook, IExecutor} from "../interfaces/IERC7579Modules.sol";

bytes32 constant EXECUTOR_MANAGER_STORAGE_SLOT = 0x1bbee3173dbdc223633258c9f337a0fff8115f206d302bea0ed3eac003b68b86;

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

    function _installExecutor(IExecutor executor, IHook hook, bytes calldata executorData, bytes calldata hookData)
        internal
    {
        if (address(hook) == address(0)) {
            hook = IHook(address(1));
        }
        ExecutorConfig storage config = _executorConfig(executor);
        config.hook = hook;
        executor.onInstall(executorData);
        if (address(hook) != address(1)) {
            hook.onInstall(hookData);
        }
    }
}
