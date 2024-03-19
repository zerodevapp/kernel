pragma solidity ^0.8.0;

import {IHook} from "../interfaces/IERC7579Modules.sol";

bytes32 constant HOOK_MANAGER_STORAGE_SLOT = 0x4605d5f70bb605094b2e761eccdc27bed9a362d8612792676bf3fb9b12832ffc;

abstract contract HookManager {
    // --- Hook ---
    // Hook is activated on these scenarios
    // - on 4337 flow, userOp.calldata starts with executeUserOp.selector && validator requires hook
    // - executeFromExecutor() is invoked and executor requires hook
    // - when fallback function has been invoked and fallback requires hook => native functions will not invoke hook
    function _doPreHook(IHook hook, bytes calldata callData) internal returns (bytes memory context) {
        context = hook.preCheck(msg.sender, callData);
    }

    function _doPostHook(IHook hook, bytes memory context, bool, /*success*/ bytes memory /*result*/ ) internal {
        // bool success, // I would like these to be enabled in erc7579, but let's skip this for now
        // bytes memory result
        hook.postCheck(context);
    }
}
