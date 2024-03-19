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
        return id == 6;
    }

    function isInitialized(address) external view virtual returns (bool); // TODO : not sure if this is the right way to do it
    function checkUserOpSignature(bytes32 id, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        virtual
        returns (uint256);
    function checkSignature(bytes32 id, address sender, bytes32 hash, bytes calldata sig)
        external
        view
        virtual
        returns (bytes4);

    function _signerOninstall(bytes32 id, bytes calldata _data) internal virtual;
    function _signerOnUninstall(bytes32 id, bytes calldata _data) internal virtual;
}
