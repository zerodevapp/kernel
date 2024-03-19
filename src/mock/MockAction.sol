pragma solidity ^0.8.0;

import {IAction} from "../interfaces/IERC7579Modules.sol";

contract MockAction is IAction {
    event MockActionEvent(address here);

    function onInstall(bytes calldata data) external payable {}

    function onUninstall(bytes calldata data) external payable {}

    function isModuleType(uint256 moduleTypeId) external view returns (bool) {}

    function isInitialized(address smartAccount) external view returns (bool) {}

    function doSomething() external {
        emit MockActionEvent(address(this));
    }
}
