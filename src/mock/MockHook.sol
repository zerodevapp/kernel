// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IHook} from "../interfaces/IERC7579Modules.sol";

contract MockHook is IHook {
    mapping(address => bytes) public data;
    mapping(address => bytes) public preHookData;
    mapping(address => bytes) public postHookData;

    function onInstall(bytes calldata _data) external payable override {
        data[msg.sender] = _data;
    }

    function onUninstall(bytes calldata) external payable override {
        delete data[msg.sender];
    }

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == 1;
    }

    function isInitialized(address smartAccount) external view override returns (bool) {
        return data[smartAccount].length > 0;
    }

    function preCheck(address msgSender, uint256 value, bytes calldata msgData)
        external
        payable
        override
        returns (bytes memory hookData)
    {
        preHookData[msg.sender] = abi.encodePacked(msgSender, msgData);
        return data[msg.sender];
    }

    function postCheck(bytes calldata hookData) external payable override {
        postHookData[msg.sender] = hookData;
    }
}
