// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IERC7579Account} from "../interfaces/IERC7579Account.sol";
import {IFallback} from "../interfaces/IERC7579Modules.sol";
import {CallType, ExecType, ExecMode, ExecLib} from "../utils/ExecLib.sol";
import {EXEC_MODE_DEFAULT} from "../types/Constants.sol";

contract Callee {
    address public lastCaller;

    function calleeTest() external {
        lastCaller = msg.sender;
    }
}

contract MockFallback is IFallback {
    mapping(address => bytes) public data;

    uint256 public valueStored;

    bool isExecutor;

    Callee public callee;

    constructor() {
        callee = new Callee();
    }

    function setExecutorMode(bool _isExecutor) external payable {
        isExecutor = _isExecutor;
    }

    function onInstall(bytes calldata _data) external payable override {
        data[msg.sender] = _data;
    }

    function onUninstall(bytes calldata) external payable override {
        delete data[msg.sender];
    }

    function isModuleType(uint256 moduleTypeId) external view override returns (bool) {
        return moduleTypeId == 3 || (isExecutor && moduleTypeId == 2);
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

    function getCaller() external pure returns (address) {
        return address(bytes20(msg.data[msg.data.length - 20:]));
    }

    function setData(uint256 value) external {
        valueStored = value;
        if (isExecutor) {
            IERC7579Account(msg.sender).executeFromExecutor(
                ExecLib.encodeSimpleSingle(),
                ExecLib.encodeSingle(address(callee), 0, abi.encodeWithSelector(Callee.calleeTest.selector))
            );
        }
    }
}
