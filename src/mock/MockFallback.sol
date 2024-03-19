// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IFallback} from "../interfaces/IERC7579Modules.sol";

contract MockFallback is IFallback {
    mapping(address => bytes) public data;

    function onInstall(bytes calldata _data) external payable override {
        data[msg.sender] = _data;
    }

    function onUninstall(bytes calldata) external payable override {
        delete data[msg.sender];
    }

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == 3;
    }

    function isInitialized(address smartAccount) external view override returns (bool) {
        return data[smartAccount].length > 0;
    }

    function fallbackFunction(uint256 v) external pure returns (uint256) {
        return v * v;
    }

    function getData() external view returns (bytes memory) {
        return data[msg.sender];
    }

    function getCaller() external view returns (address) {
        return address(bytes20(msg.data[msg.data.length - 20:]));
    }
}
