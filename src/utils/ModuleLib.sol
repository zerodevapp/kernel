// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {ExcessivelySafeCall} from "ExcessivelySafeCall/ExcessivelySafeCall.sol";
import {IModule} from "../interfaces/IERC7579Modules.sol";

library ModuleLib {
    event ModuleUninstallResult(address module, bool result);

    function uninstallModule(address module, bytes memory deinitData) internal returns (bool result) {
        (result,) = ExcessivelySafeCall.excessivelySafeCall(
            module, gasleft(), 0, 0, abi.encodeWithSelector(IModule.onUninstall.selector, deinitData)
        );
        emit ModuleUninstallResult(module, result);
    }
}
