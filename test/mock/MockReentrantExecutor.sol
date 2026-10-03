// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IExecutor} from "src/interfaces/IERC7579Modules.sol";
import {IERC7579Account} from "src/interfaces/IERC7579Account.sol";
import {MODULE_TYPE_EXECUTOR} from "src/types/Constants.sol";

/// @title MockReentrantExecutor
/// @author taek <leekt216@gmail.com>
/// @notice Executor that tries to spend the account from inside its own onUninstall callback.
/// @dev `executeFromExecutor` authorizes on the executor's `installed` flag alone, so this is the
///      probe for whether revocation happens before or after the module callback.
contract MockReentrantExecutor is IExecutor {
    address public target;
    uint256 public value;
    bool public reentryAttempted;
    bool public reentrySucceeded;

    function setReentryCall(address _target, uint256 _value) external {
        target = _target;
        value = _value;
    }

    function onInstall(bytes calldata) external payable override {}

    function onUninstall(bytes calldata) external payable override {
        reentryAttempted = true;
        try IERC7579Account(msg.sender).executeFromExecutor(bytes32(0), _executionData()) {
            reentrySucceeded = true;
        } catch {
            reentrySucceeded = false;
        }
    }

    /// @notice Same call as the reentrant one, for use while the executor is legitimately installed.
    function callExecute(address account) external returns (bytes[] memory) {
        return IERC7579Account(account).executeFromExecutor(bytes32(0), _executionData());
    }

    function isModuleType(uint256 typeId) external pure override returns (bool) {
        return typeId == MODULE_TYPE_EXECUTOR;
    }

    function isInitialized(address) external pure override returns (bool) {
        return false;
    }

    /// @dev CALLTYPE_SINGLE + EXECTYPE_DEFAULT (mode `bytes32(0)`) takes `[target|value|calldata]`.
    function _executionData() internal view returns (bytes memory) {
        return abi.encodePacked(target, value, bytes(""));
    }
}
