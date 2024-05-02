// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "../interfaces/IERC7579Modules.sol";

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

    function isModuleType(uint256 typeID) external pure returns (bool) {
        return typeID == 1;
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

    function preCheck(address msgSender, uint256 value, bytes calldata msgData)
        external
        payable
        returns (bytes memory hookData)
    {
        return hex"";
    }

    function postCheck(bytes calldata hookData) external payable {
        return;
    }
}
