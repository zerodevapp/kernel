pragma solidity ^0.8.0;

import {IPolicy} from "../interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "../interfaces/PackedUserOperation.sol";

contract MockPolicy is IPolicy {
    mapping(address => bool) public pass;
    mapping(address => bytes) public installData;
    mapping(address => bytes) public signature;

    function onInstall(bytes calldata data) external payable override {
        installData[msg.sender] = data;
    }

    function onUninstall(bytes calldata) external payable override {}

    function isModuleType(uint256 moduleTypeId) external view override returns (bool) {
        return moduleTypeId == 5;
    }

    function isInitialized(address smartAccount) external view override returns (bool) {
        return installData[smartAccount].length > 0;
    }

    function checkUserOpPolicy(PackedUserOperation calldata userOp, bytes calldata data) external payable override returns (uint256) {
        signature[msg.sender] = userOp.signature;
        return pass[msg.sender] ? 0 : 1;
    }

    function checkSignaturePolicy(address sender, bytes32 hash, bytes calldata data)
        external
        view
        override
        returns (uint256)
    {
        return pass[msg.sender] ? 0 : 1;
    }

}
