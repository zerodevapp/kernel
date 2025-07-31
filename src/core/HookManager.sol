pragma solidity ^0.8.0;

import {IHook, IFallback, IModule} from "../interfaces/IERC7579Modules.sol";
import {CallType} from "../types/Types.sol";
import {
    HOOK_MANAGER_STORAGE_SLOT,
    CALLTYPE_DELEGATECALL,
    CALLTYPE_SINGLE,
    MODULE_TYPE_FALLBACK
} from "../types/Constants.sol";
import "../types/Error.sol";

abstract contract HookManager {
    struct HookStorage {
        mapping(address => bool) enabled;
    }

    function _hookStorage() internal pure returns (HookStorage storage hs) {
        bytes32 slot = HOOK_MANAGER_STORAGE_SLOT;
        assembly {
            hs.slot := slot
        }
    }

    function _installHook(address _hook, bytes calldata _internalData, bool _installSuccess) internal {
        if (_internalData.length == 0) {
            require(_installSuccess, ModuleInstallFailed());
        }
        _hookStorage().enabled[_hook] = true;
    }

    function _uninstallHook(address _hook, bytes calldata , bool ) internal {
        _hookStorage().enabled[_hook] = false;
    }

    function _preHook(IHook _hook, bytes calldata _data) internal returns (bytes memory context) {
        if (address(_hook) != address(0)) {
            context = _hook.preCheck(msg.sender, msg.value, _data);
        }
    }

    function _postHook(IHook _hook, bytes memory context) internal {
        // bool success,
        // bytes memory result
        if (address(_hook) != address(0)) {
            _hook.postCheck(context);
        }
    }
}
