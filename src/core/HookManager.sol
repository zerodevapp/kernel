// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {IHook} from "../interfaces/IERC7579Modules.sol";
import {ModuleLib} from "../utils/ModuleLib.sol";
import {IERC7579Account} from "../interfaces/IERC7579Account.sol";
import {MODULE_TYPE_HOOK} from "../types/Constants.sol";

abstract contract HookManager {
    // NOTE: currently, all install/uninstall calls onInstall/onUninstall
    // I assume this does not pose any security risks, but there should be a way to branch if hook needs call to onInstall/onUninstall
    // --- Hook ---
    // Hook is activated on these scenarios
    // - on 4337 flow, userOp.calldata starts with executeUserOp.selector && validator requires hook
    // - executeFromExecutor() is invoked and executor requires hook
    // - when fallback function has been invoked and fallback requires hook => native functions will not invoke hook
    function _doPreHook(IHook hook, uint256 value, bytes calldata callData) internal returns (bytes memory context) {
        context = hook.preCheck(msg.sender, value, callData);
    }

    function _doPostHook(IHook hook, bytes memory context) internal {
        // bool success,
        // bytes memory result
        hook.postCheck(context);
    }

    // @notice if hook is not initialized before, kernel will call hook.onInstall no matter what flag it shows, with hookData[1:]
    // @param hookData is encoded into (1bytes flag + actual hookdata) flag is for identifying if the hook has to be initialized or not
    function _installHook(IHook hook, bytes calldata hookData) internal {
        if (address(hook) == address(0) || address(hook) == address(1)) {
            return;
        }
        if (!hook.isInitialized(address(this))) {
            // if hook is not installed, it should call onInstall
            hook.onInstall(hookData[1:]);
        } else if (bytes1(hookData[0]) == bytes1(0xff)) {
            // 0xff means you want to explicitly call install hook
            hook.onInstall(hookData[1:]);
        }
        emit IERC7579Account.ModuleInstalled(MODULE_TYPE_HOOK, address(hook));
    }

    // @param hookData encoded as (1bytes flag + actual hookdata) flag is for identifying if the hook has to be initialized or not
    function _uninstallHook(IHook hook, bytes calldata hookData) internal {
        if (address(hook) == address(0) || address(hook) == address(1)) {
            return;
        }
        if (bytes1(hookData[0]) == bytes1(0xff)) {
            // 0xff means you want to call uninstall hook
            ModuleLib.uninstallModule(address(hook), hookData[1:]);
        }
        emit IERC7579Account.ModuleUninstalled(MODULE_TYPE_HOOK, address(hook));
    }
}
