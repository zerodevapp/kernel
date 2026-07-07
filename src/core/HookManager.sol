// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IHook} from "../interfaces/IERC7579Modules.sol";
import {
    HOOK_MANAGER_STORAGE_SLOT,
    HOOK_MODULE_NOT_INSTALLED,
    HOOK_MODULE_INSTALLED_NO_HOOK
} from "../types/Constants.sol";
import {ModuleInstallFailed} from "../types/Error.sol";
import {HookStorage} from "../types/Structs.sol";

/// @title HookManager
/// @author taek <leekt216@gmail.com>
/// @notice Manages hook module installation and pre/post execution checks.
abstract contract HookManager {
    /// @notice Returns whether a hook module is enabled.
    /// @param _hook The hook to check.
    /// @return True if the hook is enabled.
    function _hookEnabled(IHook _hook) internal view virtual returns (bool) {
        return _hookStorage().enabled[address(_hook)];
    }

    /// @notice Returns the hook manager storage reference.
    function _hookStorage() internal pure returns (HookStorage storage hs) {
        bytes32 slot = HOOK_MANAGER_STORAGE_SLOT;
        assembly {
            hs.slot := slot
        }
    }

    /// @notice Installs a hook module by marking it as enabled.
    /// @param _hook The hook module address.
    /// @param _internalData If empty, requires onInstall success; otherwise ignored.
    /// @param _installSuccess Whether the module's onInstall succeeded.
    function _installHook(address _hook, bytes calldata _internalData, bool _installSuccess) internal {
        if (_internalData.length == 0) {
            require(_installSuccess, ModuleInstallFailed());
        }
        _hookStorage().enabled[_hook] = true;
    }

    /// @notice Uninstalls a hook module by marking it as disabled.
    /// @param _hook The hook module address.
    function _uninstallHook(address _hook, bytes calldata, bool) internal {
        _hookStorage().enabled[_hook] = false;
    }

    /// @notice Executes the hook's preCheck if the hook is a real module (not sentinel values).
    /// @param _hook The hook to call.
    /// @param _data The calldata to pass to the hook's preCheck.
    /// @return context The context data returned by the hook for use in postCheck.
    function _preHook(IHook _hook, bytes calldata _data) internal returns (bytes memory context) {
        if (address(_hook) != HOOK_MODULE_INSTALLED_NO_HOOK && address(_hook) != HOOK_MODULE_NOT_INSTALLED) {
            context = _hook.preCheck(msg.sender, msg.value, _data);
        }
    }

    /// @notice Executes the hook's postCheck if the hook is a real module.
    /// @param _hook The hook to call.
    /// @param context The context data from preCheck.
    function _postHook(IHook _hook, bytes memory context) internal {
        if (address(_hook) != HOOK_MODULE_INSTALLED_NO_HOOK && address(_hook) != HOOK_MODULE_NOT_INSTALLED) {
            _hook.postCheck(context);
        }
    }
}
