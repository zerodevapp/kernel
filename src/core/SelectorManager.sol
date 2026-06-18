// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IHook} from "../interfaces/IERC7579Modules.sol";
import {CallType} from "../types/Types.sol";
import {
    SELECTOR_MANAGER_STORAGE_SLOT,
    CALLTYPE_DELEGATECALL,
    HOOK_MODULE_NOT_INSTALLED,
    HOOK_MODULE_INSTALLED_NO_HOOK
} from "../types/Constants.sol";
import {ModuleInstallFailed, NotInstalled, InvalidSelectorTarget} from "../types/Error.sol";
import {SelectorConfig, SelectorStorage} from "../types/Structs.sol";

/// @title SelectorManager
/// @author taek <leekt216@gmail.com>
/// @notice Manages fallback module routing by function selector, including call type and hook configuration.
abstract contract SelectorManager {
    function _hookEnabled(IHook _hook) internal view virtual returns (bool);

    /// @notice Returns the fallback selector configuration for a given selector.
    /// @param selector The 4-byte function selector.
    /// @return The SelectorConfig (hook, target, callType).
    function selectorConfig(bytes4 selector) external view returns (SelectorConfig memory) {
        return _selectorConfig(selector);
    }

    /// @notice Returns the storage reference for a selector's configuration.
    function _selectorConfig(bytes4 selector) internal view returns (SelectorConfig storage config) {
        config = _selectorStorage().selectorConfig[selector];
    }

    function _selectorStorage() internal pure returns (SelectorStorage storage ss) {
        bytes32 slot = SELECTOR_MANAGER_STORAGE_SLOT;
        assembly {
            ss.slot := slot
        }
    }

    /// @notice Installs a fallback selector handler.
    /// @dev internalData format: `[bytes4 selector | bytes1 callType | bytes20 hookAddress]`.
    /// @param _module The fallback module address.
    /// @param _internalData Packed selector, call type, and hook address.
    /// @param _installSuccess Whether the module's onInstall call succeeded (required for non-delegatecall).
    function _installSelector(address _module, bytes calldata _internalData, bool _installSuccess) internal {
        require(_module != address(0), InvalidSelectorTarget());
        CallType callType = CallType.wrap(bytes1(_internalData[4]));
        require(callType == CALLTYPE_DELEGATECALL || _installSuccess, ModuleInstallFailed());
        bytes4 selector = bytes4(_internalData[0:4]);
        address hook = address(bytes20(_internalData[5:25]));
        // address(0) = entryPoint-only (no hook), address(1) = anyone (no hook), else = real hook
        if (hook != HOOK_MODULE_NOT_INSTALLED && hook != HOOK_MODULE_INSTALLED_NO_HOOK) {
            require(_hookEnabled(IHook(hook)), NotInstalled());
        }
        SelectorConfig storage $ = _selectorConfig(selector);
        $.target = _module;
        $.callType = callType;
        $.hook = IHook(hook);
    }

    /// @notice Uninstalls a fallback selector handler by zeroing its configuration.
    /// @param _internalData Must contain the selector in the first 4 bytes.
    function _uninstallSelector(address, bytes calldata _internalData, bool) internal {
        bytes4 selector = bytes4(_internalData[0:4]);
        SelectorConfig storage $ = _selectorConfig(selector);
        $.target = address(0);
        $.callType = CallType.wrap(bytes1(0x00));
        $.hook = IHook(address(0));
    }
}
