// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IHook} from "../interfaces/IERC7579Modules.sol";
import {CallType} from "../types/Types.sol";
import {SELECTOR_MANAGER_STORAGE_SLOT, CALLTYPE_DELEGATECALL} from "../types/Constants.sol";
import {ModuleInstallFailed} from "../types/Error.sol";

abstract contract SelectorManager {
    struct SelectorConfig {
        IHook hook; // 20 bytes for hook address
        address target; // 20 bytes target will be fallback module, called with call
        CallType callType;
    }

    struct SelectorStorage {
        mapping(bytes4 => SelectorConfig) selectorConfig;
    }

    function selectorConfig(bytes4 selector) external view returns (SelectorConfig memory) {
        return _selectorConfig(selector);
    }

    function _selectorConfig(bytes4 selector) internal view returns (SelectorConfig storage config) {
        config = _selectorStorage().selectorConfig[selector];
    }

    function _selectorStorage() internal pure returns (SelectorStorage storage ss) {
        bytes32 slot = SELECTOR_MANAGER_STORAGE_SLOT;
        assembly {
            ss.slot := slot
        }
    }

    function _installSelector(address _module, bytes calldata _internalData, bool _installSuccess) internal {
        CallType callType = CallType.wrap(bytes1(_internalData[4]));
        require(callType == CALLTYPE_DELEGATECALL || _installSuccess, ModuleInstallFailed());
        bytes4 selector = bytes4(_internalData[0:4]);
        address hook = address(bytes20(_internalData[5:25]));
        SelectorConfig storage $ = _selectorConfig(selector);
        $.target = _module;
        $.callType = callType;
        $.hook = IHook(hook);
    }

    function _uninstallSelector(address _module, bytes calldata _internalData, bool _uninstallSuccess) internal {
        bytes4 selector = bytes4(_internalData[0:4]);
        SelectorConfig storage $ = _selectorConfig(selector);
        $.target = address(0);
        $.callType = CallType.wrap(bytes1(0x00));
        $.hook = IHook(address(0));
    }
}
