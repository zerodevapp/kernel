pragma solidity ^0.8.0;

import "../types/Types.sol";
import "../types/Constants.sol";
import "../interfaces/IERC7579Modules.sol";

contract ExecutorManager {
    error NotExecutor();

    struct ExecutorConfig {
        IHook hook; // address(1) : hook not required, address(0) : validator not installed
    }

    struct ExecutorStorage {
        mapping(IExecutor => ExecutorConfig) executorConfig;
    }

    function _executorStorage() internal view returns (ExecutorStorage storage $) {
        assembly {
            $.slot := EXECUTOR_MANAGER_STORAGE_SLOT
        }
    }

    function executorConfig(address executor) external view returns (ExecutorConfig memory) {
        return _executorConfig(IExecutor(executor));
    }

    function _executorConfig(IExecutor executor) internal view returns (ExecutorConfig storage config) {
        config = _executorStorage().executorConfig[executor];
    }

    function _installExecutor(address _executor, bytes calldata _internalData, bool _installSuccess) internal {
        // NOTE: we don't care if install was successful
        address hook = _internalData.length >= 20 ? address(bytes20(_internalData[0:20])) : address(0);
        if (hook == address(0)) {
            hook = address(1); // address(1) indicates it is installed and does not require any hook
        }
        _executorConfig(IExecutor(_executor)).hook = IHook(hook);
    }

    function _uninstallExecutor(address _executor, bytes calldata _internalData, bool _installSuccess) internal {
        _executorConfig(IExecutor(_executor)).hook = IHook(address(0));
    }
}
