// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {CallType} from "../types/Types.sol";
import {SELECTOR_MANAGER_STORAGE_SLOT, CALLTYPE_DELEGATECALL} from "../types/Constants.sol";
import {
    ModuleInstallFailed,
    InvalidSelectorTarget,
    InvalidDataLength,
    ScopedExecutionHookStillInstalled
} from "../types/Error.sol";
import {SelectorConfig, SelectorStorage} from "../types/Structs.sol";

/// @title SelectorManager
/// @author taek <leekt216@gmail.com>
/// @notice Manages fallback module routing by function selector.
abstract contract SelectorManager {
    /// @notice Returns the fallback selector configuration for a given selector.
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
    /// @dev internalData format: `[bytes4 selector | bytes1 callType]`.
    ///      Selectors handled natively by Kernel are valid to install, but native dispatch takes precedence,
    ///      so their selector configuration and scoped execution hook have no effect.
    function _installSelector(address _module, bytes calldata _internalData, bool _installSuccess) internal {
        require(_internalData.length == 5, InvalidDataLength());
        require(_module != address(0), InvalidSelectorTarget());
        bytes4 selector = bytes4(_internalData[0:4]);
        CallType callType = CallType.wrap(bytes1(_internalData[4]));
        require(callType == CALLTYPE_DELEGATECALL || _installSuccess, ModuleInstallFailed());
        SelectorConfig storage $ = _selectorConfig(selector);
        $.target = _module;
        $.callType = callType;
    }

    /// @notice Uninstalls a fallback selector handler.
    function _uninstallSelector(address, bytes calldata _internalData, bool) internal {
        require(_internalData.length == 4, InvalidDataLength());
        SelectorConfig storage $ = _selectorConfig(bytes4(_internalData[0:4]));
        require(address($.scopedExecutionHook) == address(0), ScopedExecutionHookStillInstalled());
        $.target = address(0);
        $.callType = CallType.wrap(bytes1(0x00));
    }
}
