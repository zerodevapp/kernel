pragma solidity ^0.8.0;

import {IHook} from "../interfaces/IERC7579Modules.sol";
import {CallType} from "../utils/ExecLib.sol";

abstract contract SelectorManager {
    struct SelectorConfig {
        bytes4 group; // group of this selector action
        IHook hook; // 20 bytes for hook address
        CallType callType; //1 bytes
        address target; // 20 bytes target will be fallback module, called with delegatecall or call
    }

    mapping(bytes4 selector => SelectorConfig) public selectorConfig;

    function _installSelector(bytes4 selector, bytes4 group, IHook hook, CallType callType, address target) internal {
        selectorConfig[selector] = SelectorConfig({group: group, hook: hook, callType: callType, target: target});
        // TODO : INSTALL FLOW IS NOT SUPPORTED YET
    }
}
