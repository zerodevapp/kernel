pragma solidity ^0.8.0;

import {IHook} from "../interfaces/IERC7579Modules.sol";
import {CallType} from "../utils/ExecLib.sol";
import {CALLTYPE_DELEGATECALL} from "../types/Constants.sol";

// bytes32(uint256(keccak256('kernel.v3.selector')) - 1)
bytes32 constant SELECTOR_MANAGER_STORAGE_SLOT = 0x7c341349a4360fdd5d5bc07e69f325dc6aaea3eb018b3e0ea7e53cc0bb0d6f3b;

abstract contract SelectorManager {
    struct SelectorConfig {
        bytes4 group; // group of this selector action
        IHook hook; // 20 bytes for hook address
        CallType callType; //1 bytes
        address target; // 20 bytes target will be fallback module, called with delegatecall or call
    }

    struct SelectorStorage {
        mapping(bytes4 => SelectorConfig) selectorConfig;
    }

    function _selectorConfig(bytes4 selector) internal view returns (SelectorConfig storage config) {
        SelectorStorage storage ss;
        bytes32 slot = SELECTOR_MANAGER_STORAGE_SLOT;
        assembly {
            ss.slot := slot
        }
        config = ss.selectorConfig[selector];
    }

    function _installSelector(bytes4 selector, bytes4 group, address target, IHook hook, bytes calldata hookData)
        internal
    {
        if (address(hook) == address(0)) {
            hook = IHook(address(1));
        }
        SelectorConfig storage ss = _selectorConfig(selector);
        // we are going to install only through delegatecall
        ss.group = group;
        ss.hook = hook;
        ss.callType = CALLTYPE_DELEGATECALL;
        ss.target = target;
        // TODO : INSTALL FLOW FOR fallback is NOT SUPPORTED YET
        if (address(hook) != address(1)) {
            hook.onInstall(hookData);
        }
    }
}
