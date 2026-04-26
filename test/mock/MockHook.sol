// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IHook} from "src/interfaces/IERC7579Modules.sol";

contract MockHook is IHook {
    error PreHookReverted();
    error PostHookReverted();

    mapping(address => bytes) public data;
    mapping(address => bytes) public preHookData;
    mapping(address => bytes) public postHookData;
    bool public installCalled;

    // State for BTT testing
    bool private _preHookCalled;
    bool private _postHookCalled;
    bool private _revertOnPreHook;
    bool private _revertOnPostHook;

    function onInstall(bytes calldata _data) external payable override {
        data[msg.sender] = _data;
        installCalled = true;
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

    function preCheck(address msgSender, uint256, bytes calldata msgData)
        external
        payable
        override
        returns (bytes memory hookData)
    {
        if (_revertOnPreHook) {
            revert PreHookReverted();
        }
        _preHookCalled = true;
        preHookData[msg.sender] = abi.encodePacked(msgSender, msgData);
        return data[msg.sender];
    }

    function postCheck(bytes calldata hookData) external payable override {
        if (_revertOnPostHook) {
            revert PostHookReverted();
        }
        _postHookCalled = true;
        postHookData[msg.sender] = hookData;
    }

    // BTT helper functions
    function preHookCalled() external view returns (bool) {
        return _preHookCalled;
    }

    function postHookCalled() external view returns (bool) {
        return _postHookCalled;
    }

    function setRevertOnPreHook(bool shouldRevert) external {
        _revertOnPreHook = shouldRevert;
    }

    function setRevertOnPostHook(bool shouldRevert) external {
        _revertOnPostHook = shouldRevert;
    }

    function resetState() external {
        _preHookCalled = false;
        _postHookCalled = false;
        _revertOnPreHook = false;
        _revertOnPostHook = false;
    }
}
