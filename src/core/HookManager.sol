pragma solidity ^0.8.0;

import {IHook} from "../interfaces/IERC7579Modules.sol";

abstract contract HookManager {
    // --- Hook ---
    // Hook is activated on these scenarios
    // - on 4337 flow, userOp.calldata starts with executeUserOp.selector && validator requires hook
    // - executeFromExecutor() is invoked and executor requires hook
    // - when fallback function has been invoked and fallback requires hook => native functions will not invoke hook
    function _doPreHook(IHook hook, bytes calldata callData) internal returns (bytes memory context) {
        context = hook.preCheck(msg.sender, callData);
    }

    function _doPostHook(IHook hook, bytes memory context)
        // bool success, // I would like these to be enabled in erc7579, but let's skip this for now
        // bytes memory result
        internal
    {
        hook.postCheck(context);
    }
}
