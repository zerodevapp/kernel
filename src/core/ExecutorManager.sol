pragma solidity ^0.8.0;

import {EXECUTOR_MANAGER_STORAGE_SLOT} from "../types/Constants.sol";
import {IExecutor, IHook} from "../interfaces/IERC7579Modules.sol";
import {ExecutorStorage, ExecutorConfig} from "../types/Structs.sol";

contract ExecutorManager {
    error NotExecutor();

    function _executorStorage() internal pure returns (ExecutorStorage storage $) {
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

    function _installExecutor(address _executor, bytes calldata _internalData, bool) internal {
        // NOTE: we don't care if install was successful
        address hook = _internalData.length >= 20 ? address(bytes20(_internalData[0:20])) : address(0);
        if (hook == address(0)) {
            hook = address(1); // address(1) indicates it is installed and does not require any hook
        }
        _executorConfig(IExecutor(_executor)).hook = IHook(hook);
    }

    function _uninstallExecutor(address _executor, bytes calldata, bool) internal {
        _executorConfig(IExecutor(_executor)).hook = IHook(address(0));
    }
}
