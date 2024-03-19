// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ISigner} from "../../interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "../../interfaces/PackedUserOperation.sol";

abstract contract SignerBase is ISigner {
    function onInstall(bytes calldata data) external payable {
        bytes32 id = bytes32(data[0:32]);
        bytes calldata _data = data[32:];
        _signerOninstall(id, _data);
    }

    function onUninstall(bytes calldata data) external payable {
        bytes32 id = bytes32(data[0:32]);
        bytes calldata _data = data[32:];
        _signerOnUninstall(id, _data);
    }

    function isModuleType(uint256 id) external pure returns (bool) {
        return id == 5;
    }

    function isInitialized(address) external view virtual returns (bool); // TODO : not sure if this is the right way to do it
    function checkUserOpPolicy(bytes32, PackedUserOperation calldata) external payable virtual returns (uint256);
    function checkSignaturePolicy(bytes32, address, bytes32, bytes calldata) external view virtual returns (uint256);

    function _signerOninstall(bytes32 id, bytes calldata _data) internal virtual;
    function _signerOnUninstall(bytes32 id, bytes calldata _data) internal virtual;
}
