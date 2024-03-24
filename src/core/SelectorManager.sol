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
        fallbackHandler = _selectorStorage().fallbackHandler;
        hook = _selectorStorage().hook;
    }

    function _selectorConfig(bytes4 selector) internal view returns (SelectorConfig storage config) {
        config = _selectorStorage().selectorConfig[selector];
    }

    function _selectorStorage() internal view returns (SelectorStorage storage ss) {
        bytes32 slot = SELECTOR_MANAGER_STORAGE_SLOT;
        assembly {
            ss.slot := slot
        }
    }

    function _installSelector(bytes4 selector, address target, IHook hook) internal {
        if (address(hook) == address(0)) {
            hook = IHook(address(1));
        }
        SelectorConfig storage ss = _selectorConfig(selector);
        // we are going to install only through delegatecall
        ss.hook = hook;
        ss.target = target;
    }

    function _uninstallSelector(bytes4 selector) internal returns (IHook hook) {
        SelectorConfig storage ss = _selectorConfig(selector);
        hook = ss.hook;
        ss.hook = IHook(address(0));
        ss.target = address(0);
    }

    function _installFallback(IFallback fallbackHandler, bytes calldata fallbackData, IHook hook) internal {
        if (address(hook) == address(0)) {
            hook = IHook(address(1));
        }
        _selectorStorage().fallbackHandler = fallbackHandler;
        fallbackHandler.onInstall(fallbackData);
        _selectorStorage().hook = hook;
    }

    function _uninstallFallback(bytes calldata fallbackDeinitData) internal returns (IHook hook) {
        SelectorStorage storage ss = _selectorStorage();
        hook = ss.hook;
        ss.hook = IHook(address(0));
        ss.fallbackHandler = IFallback(address(0));
    }
}
