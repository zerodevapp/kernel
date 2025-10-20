pragma solidity ^0.8.0;

import {IHook} from "../interfaces/IERC7579Modules.sol";
import {HOOK_MANAGER_STORAGE_SLOT} from "../types/Constants.sol";
import {ModuleInstallFailed} from "../types/Error.sol";
import {HookStorage} from "../types/Structs.sol";

abstract contract HookManager {
    function _hookEnabled(IHook _hook) internal view virtual returns (bool) {
        return _hookStorage().enabled[address(_hook)];
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

    function _uninstallHook(address _hook, bytes calldata, bool) internal {
        _hookStorage().enabled[_hook] = false;
    }

    function _preHook(IHook _hook, bytes calldata _data) internal returns (bytes memory context) {
        if (address(_hook) != address(1) && address(_hook) != address(0)) {
            context = _hook.preCheck(msg.sender, msg.value, _data);
        }
    }

    function _postHook(IHook _hook, bytes memory context) internal {
        // bool success,
        // bytes memory result
        if (address(_hook) != address(1) && address(_hook) != address(0)) {
            _hook.postCheck(context);
        }
    }
}
