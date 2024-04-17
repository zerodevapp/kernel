// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract MockAction {
    event MockActionEvent(address here);

    function onInstall(bytes calldata data) external payable {}

    function onUninstall(bytes calldata data) external payable {}

    function isModuleType(uint256 moduleTypeId) external view returns (bool) {}

    function isInitialized(address smartAccount) external view returns (bool) {}

    function doSomething() external {
        emit MockActionEvent(address(this));
    }
}
