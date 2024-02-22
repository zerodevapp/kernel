pragma solidity ^0.8.0;

import {IHook, IExecutor} from "../interfaces/IERC7579Modules.sol";

abstract contract ExecutorManager {
    struct ExecutorConfig {
        bytes4 group;
        IHook hook; // address(1) : hook not required, address(0) : validator not installed
    }

    mapping(IExecutor executor => ExecutorConfig) public executorConfig;

    function _installExecutor(IExecutor executor, bytes4 group, IHook hook, bytes calldata data) internal {
        executorConfig[executor] = ExecutorConfig({group: group, hook: hook});
        executor.onInstall(data);
    }
}
