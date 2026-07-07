// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IValidator} from "src/interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

contract MockRevertingValidator is IValidator {
    error InstallFailed();

    function onInstall(bytes calldata) external payable {
        revert InstallFailed();
    }

    function onUninstall(bytes calldata) external payable {}

    function isModuleType(uint256 typeId) external pure returns (bool) {
        return typeId == 1;
    }

    function isInitialized(address) external pure returns (bool) {
        return false;
    }

    function validateUserOp(PackedUserOperation calldata, bytes32) external payable returns (uint256) {
        return 0;
    }

    function isValidSignatureWithSender(address, bytes32, bytes calldata) external pure returns (bytes4) {
        return 0x1626ba7e;
    }
}
