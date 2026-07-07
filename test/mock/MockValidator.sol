// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {IValidator, IHook} from "src/interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

/// @notice Mock validator that returns empty data (misconfigured validator)
contract MockEmptyReturnValidator is IValidator {
    function onInstall(bytes calldata) external payable {}
    function onUninstall(bytes calldata) external payable {}

    function isModuleType(uint256 typeId) external pure returns (bool) {
        return typeId == 1;
    }

    function isInitialized(address) external pure returns (bool) {
        return true;
    }

    function validateUserOp(PackedUserOperation calldata, bytes32) external payable returns (uint256) {
        // Return success but with no return data (simulates misconfigured validator)
        assembly {
            return(0, 0)
        }
    }

    function isValidSignatureWithSender(address, bytes32, bytes calldata) external pure returns (bytes4) {
        return 0x1626ba7e;
    }
}

contract MockValidator is IValidator, IHook {
    mapping(address => bool) public initialized;
    bool public success;
    uint256 public count;
    bool public installCalled;

    mapping(address => bytes) public validatorData;
    mapping(bytes32 => bool) public validSig;

    bool public isHook;
    uint256 public customValidationData;

    function setHook(bool _isHook) external {
        isHook = _isHook;
    }

    function sudoSetSuccess(bool _success) external {
        success = _success;
    }

    function sudoSetValidSig(bytes calldata sig) external {
        validSig[keccak256(sig)] = true;
    }

    function sudoSetValidationData(uint256 _validationData) external {
        customValidationData = _validationData;
    }

    function onInstall(bytes calldata data) external payable {
        initialized[msg.sender] = true;
        validatorData[msg.sender] = data;
        installCalled = true;
    }

    function onUninstall(bytes calldata data) external payable {
        initialized[msg.sender] = false;
        validatorData[msg.sender] = data;
    }

    function isModuleType(uint256 typeId) external pure returns (bool) {
        return typeId == 1;
    }

    /**
     * @dev Returns if the module was already initialized for a provided smartaccount
     */
    function isInitialized(address smartAccount) external view returns (bool) {
        return initialized[smartAccount];
    }

    function validateUserOp(PackedUserOperation calldata, bytes32) external payable returns (uint256) {
        count++;

        // If customValidationData is set, return it (allows testing time bounds)
        if (customValidationData != 0) {
            return customValidationData;
        }

        if (success) {
            return 0;
        } else {
            return 1;
        }
    }

    function isValidSignatureWithSender(address, bytes32, bytes calldata sig) external view returns (bytes4) {
        if (validSig[keccak256(sig)] == true) {
            return 0x1626ba7e;
        } else {
            return 0xffffffff;
        }
    }

    function validateSignatureWithDataWithSender(address, bytes32, bytes calldata, bytes calldata)
        external
        view
        returns (bool)
    {
        return success;
    }

    function preCheck(address, uint256, bytes calldata) external payable returns (bytes memory) {
        return hex"";
    }

    function postCheck(bytes calldata) external payable {
        return;
    }
}
