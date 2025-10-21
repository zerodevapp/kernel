// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {IValidator, IHook} from "src/interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

contract MockValidator is IValidator, IHook {
    mapping(address => bool) public initialized;
    bool public success;
    uint256 public count;

    mapping(address => bytes) public validatorData;
    mapping(bytes32 => bool) public validSig;

    bool public isHook;

    function setHook(bool _isHook) external {
        isHook = _isHook;
    }

    function sudoSetSuccess(bool _success) external {
        success = _success;
    }

    function sudoSetValidSig(bytes calldata sig) external {
        validSig[keccak256(sig)] = true;
    }

    function onInstall(bytes calldata data) external payable {
        initialized[msg.sender] = true;
        validatorData[msg.sender] = data;
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
