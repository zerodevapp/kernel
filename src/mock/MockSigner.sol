// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "../interfaces/IERC7579Modules.sol";

contract MockSigner is ISigner {
    mapping(address wallet => bytes) public data;
    mapping(address => mapping(bytes32 => bytes)) public sig;
    mapping(address => mapping(bytes32 => bool)) public pass;

    function sudoSetValidSig(address _wallet, bytes32 _id, bytes calldata _sig) external payable {
        sig[_wallet][_id] = _sig;
    }

    function sudoSetPass(address _wallet, bytes32 _id, bool _flag) external payable {
        pass[_wallet][_id] = _flag;
    }

    function onInstall(bytes calldata _data) external payable override {
        data[msg.sender] = _data;
    }

    function onUninstall(bytes calldata) external payable override {}

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        if (moduleTypeId == 7) {
            return true;
        } else {
            return false;
        }
    }

    function isInitialized(address smartAccount) external view override returns (bool) {
        return data[smartAccount].length > 0;
    }

    function checkUserOpSignature(bytes32 id, PackedUserOperation calldata userOp, bytes32)
        external
        payable
        override
        returns (uint256)
    {
        return keccak256(userOp.signature) == keccak256(sig[msg.sender][id]) ? 0 : 1;
    }

    function checkSignature(bytes32 id, address, bytes32, bytes calldata) external view override returns (bytes4) {
        if (pass[msg.sender][id] == true) {
            return 0x1626ba7e;
        } else {
            return 0xffffffff;
        }
    }
}
