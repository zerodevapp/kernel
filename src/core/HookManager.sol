pragma solidity ^0.8.0;

import {IHook, IFallback, IModule} from "../interfaces/IERC7579Modules.sol";
import {CallType} from "../types/Types.sol";
import {
    SELECTOR_MANAGER_STORAGE_SLOT,
    CALLTYPE_DELEGATECALL,
    CALLTYPE_SINGLE,
    MODULE_TYPE_FALLBACK
} from "../types/Constants.sol";
import "../types/Error.sol";

abstract contract HookManager {
    function _installHook(address _hook, bytes calldata _internalData, bool _installSuccess) internal {
        if(_internalData.length == 0) {
            require(_installSuccess, ModuleInstallFailed());
        }
    }

    function _uninstallHook(address _hook, bytes calldata _internalData, bool _uninstallSuccess) internal {
        // no-op
    }

    function _preHook(IHook _hook) internal returns(bytes memory context){
        require(address(_hook) != address(0), NotInstalled());
        if(address(_hook) != address(1)) {
            context = _hook.preCheck(msg.sender, msg.value, msg.data);
        }
    }
    function _postHook(IHook _hook, bytes memory context) internal {
        // bool success,
        // bytes memory result
        if(address(_hook) != address(1)) {
            _hook.postCheck(context);
        }
    }
}
