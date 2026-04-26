// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IPolicy} from "src/interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

contract MockRevertingPolicy is IPolicy {
    error InstallFailed();

    function onInstall(bytes calldata) external payable {
        revert InstallFailed();
    }

    function onUninstall(bytes calldata) external payable {}

    function isModuleType(uint256 typeId) external pure returns (bool) {
        return typeId == 5;
    }

    function isInitialized(address) external pure returns (bool) {
        return false;
    }

    function checkUserOpPolicy(bytes32, PackedUserOperation calldata) external payable returns (uint256) {
        return 0;
    }

    function checkSignaturePolicy(bytes32, address, bytes32, bytes calldata) external pure returns (uint256) {
        return 0;
    }
}
