pragma solidity ^0.8.0;

import {IHook, IFallback} from "../interfaces/IERC7579Modules.sol";
import {CallType} from "../utils/ExecLib.sol";
import {CALLTYPE_DELEGATECALL} from "../types/Constants.sol";

// bytes32(uint256(keccak256('kernel.v3.selector')) - 1)
bytes32 constant SELECTOR_MANAGER_STORAGE_SLOT = 0x7c341349a4360fdd5d5bc07e69f325dc6aaea3eb018b3e0ea7e53cc0bb0d6f3b;

abstract contract SelectorManager {
    struct SelectorConfig {
        IHook hook; // 20 bytes for hook address
        address target; // 20 bytes target will be fallback module, called with delegatecall or call
    }

    struct SelectorStorage {
        IFallback fallbackHandler;
        IHook hook;
        mapping(bytes4 => SelectorConfig) selectorConfig;
    }

    function selectorConfig(bytes4 selector) external view returns (SelectorConfig memory) {
        return _selectorConfig(selector);
    }

    function fallbackConfig() external view returns (IFallback, IHook) {
        return _fallbackConfig();
    }

    function _fallbackConfig() internal view returns (IFallback fallbackHandler, IHook hook) {
        SelectorStorage storage ss;
        bytes32 slot = SELECTOR_MANAGER_STORAGE_SLOT;
        assembly {
            ss.slot := slot
        }
        fallbackHandler = ss.fallbackHandler;
        hook = ss.hook;
    }

    function _selectorConfig(bytes4 selector) internal view returns (SelectorConfig storage config) {
        SelectorStorage storage ss;
        bytes32 slot = SELECTOR_MANAGER_STORAGE_SLOT;
        assembly {
            ss.slot := slot
        }
        config = ss.selectorConfig[selector];
    }

    function _installSelector(bytes4 selector, address target, IHook hook, bytes calldata hookData) internal {
        if (address(hook) == address(0)) {
            hook = IHook(address(1));
        }
        SelectorConfig storage ss = _selectorConfig(selector);
        // we are going to install only through delegatecall
        ss.hook = hook;
        ss.target = target;
        // TODO : INSTALL FLOW FOR fallback is NOT SUPPORTED YET
        if (address(hook) != address(1)) {
            hook.onInstall(hookData);
        }
    }

    function _installFallback(
        IFallback fallbackHandler,
        IHook hook,
        bytes calldata fallbackData,
        bytes calldata hookData
    ) internal {
        if (address(hook) == address(0)) {
            hook = IHook(address(1));
        }
        SelectorStorage storage ss;
        bytes32 slot = SELECTOR_MANAGER_STORAGE_SLOT;
        assembly {
            ss.slot := slot
        }
        ss.fallbackHandler = fallbackHandler;
        fallbackHandler.onInstall(fallbackData);
        ss.hook = hook;
        if (address(hook) != address(1)) {
            hook.onInstall(hookData);
        }
    }
}
