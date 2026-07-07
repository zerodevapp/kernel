// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {IPolicy} from "src/interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

contract MockPolicy is IPolicy {
    mapping(address => mapping(bytes32 => bool)) public pass;
    mapping(address => bytes) public installData;
    mapping(address => mapping(bytes32 => bytes)) public sig;
    bool success;
    uint256 public customValidationData;

    function onInstall(bytes calldata data) external payable override {
        installData[msg.sender] = data;
    }

    function onUninstall(bytes calldata) external payable override {}

    function sudoSetValidSig(address _wallet, bytes32 _id, bytes calldata _sig) external payable {
        sig[_wallet][_id] = _sig;
    }

    function sudoSetPass(address _wallet, bytes32 _id, bool _pass) external payable {
        success = _pass;
        pass[_wallet][_id] = _pass;
    }

    function sudoSetValidationData(uint256 _validationData) external {
        customValidationData = _validationData;
    }

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == 5;
    }

    function isInitialized(address smartAccount) external view override returns (bool) {
        return installData[smartAccount].length > 0;
    }

    function checkUserOpPolicy(bytes32 id, PackedUserOperation calldata userOp)
        external
        payable
        override
        returns (uint256)
    {
        // If customValidationData is set, return it (allows testing time bounds intersection)
        if (customValidationData != 0) {
            return customValidationData;
        }
        return keccak256(userOp.signature) == keccak256(sig[msg.sender][id]) ? 0 : 1;
    }

    function checkSignaturePolicy(bytes32 id, address, bytes32, bytes calldata)
        external
        view
        override
        returns (uint256)
    {
        return pass[msg.sender][id] ? 0 : 1;
    }

    function validateSignatureWithDataWithSender(address, bytes32, bytes calldata signature, bytes calldata)
        external
        view
        returns (bool)
    {
        return success;
    }
}
