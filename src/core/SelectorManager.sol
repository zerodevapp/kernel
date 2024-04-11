// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {IHook, IFallback, IModule} from "../interfaces/IERC7579Modules.sol";
import {CallType} from "../utils/ExecLib.sol";
import {SELECTOR_MANAGER_STORAGE_SLOT, CALLTYPE_DELEGATECALL, CALLTYPE_SINGLE} from "../types/Constants.sol";
import {ModuleLib} from "../utils/ModuleLib.sol";

abstract contract SelectorManager {
    error NotSupportedCallType();

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

    function _installSelector(bytes4 selector, address target, IHook hook, bytes calldata selectorData) internal {
        if (address(hook) == address(0)) {
            hook = IHook(address(1));
        }
        SelectorConfig storage ss = _selectorConfig(selector);
        // we are going to install only through call/delegatecall
        CallType callType = CallType.wrap(bytes1(selectorData[0]));
        if (callType == CALLTYPE_SINGLE) {
            IModule(target).onInstall(selectorData[1:]);
        } else if (callType != CALLTYPE_DELEGATECALL) {
            // NOTE : we are not going to call onInstall for delegatecall, and we support only CALL & DELEGATECALL
            revert NotSupportedCallType();
        }
        ss.hook = hook;
        ss.target = target;
        ss.callType = callType;
    }

    function _uninstallSelector(bytes4 selector, bytes calldata selectorDeinitData) internal returns (IHook hook) {
        SelectorConfig storage ss = _selectorConfig(selector);
        hook = ss.hook;
        ss.hook = IHook(address(0));
        ModuleLib.uninstallModule(ss.target, selectorDeinitData);
        ss.target = address(0);
        ss.callType = CallType.wrap(bytes1(0xff));
    }
}
