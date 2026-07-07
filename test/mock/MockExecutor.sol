// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IExecutor} from "src/interfaces/IERC7579Modules.sol";
import {IERC7579Account} from "src/interfaces/IERC7579Account.sol";
import {Kernel} from "src/Kernel.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";
import {Call} from "src/types/Structs.sol";
import {MockCallee} from "./MockCallee.sol";
import {MockAction} from "./MockAction.sol";

contract MockExecutor is IExecutor {
    mapping(address => bytes) public data;
    bool public installCalled;
    MockAction public action;

    event Results(uint256 index, bytes result);

    constructor() {
        action = new MockAction();
    }

    function onInstall(bytes calldata _data) external payable override {
        data[msg.sender] = _data;
        installCalled = true;
    }

    function onUninstall(bytes calldata) external payable override {
        delete data[msg.sender];
    }

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == 2;
    }

    function isInitialized(address smartAccount) external view override returns (bool) {
        return data[smartAccount].length > 0;
    }

    function sudoDoExec(IERC7579Account account, bytes32 mode, bytes calldata executionCalldata) external payable {
        bytes[] memory results = account.executeFromExecutor(mode, executionCalldata);
        for (uint256 i = 0; i < results.length; i++) {
            emit Results(i, results[i]);
        }
    }

    /// @notice Execute a single call via kernel
    function executeViaKernel(
        Kernel kernel,
        bytes1 callType,
        bytes1 execType,
        address target,
        uint256 value,
        bytes4 selector
    ) external returns (bytes[] memory) {
        bytes32 mode = bytes32(abi.encodePacked(callType, execType, bytes4(0), bytes4(0), bytes22(0)));
        bytes memory executionData = abi.encodePacked(target, value, selector);
        return kernel.executeFromExecutor(mode, executionData);
    }

    /// @notice Execute a single call via kernel with custom callType
    function executeViaKernelWithCallType(Kernel kernel, bytes1 callType, bytes1 execType)
        external
        returns (bytes[] memory)
    {
        bytes32 mode = bytes32(abi.encodePacked(callType, execType, bytes4(0), bytes4(0), bytes22(0)));
        bytes memory executionData = abi.encodePacked(address(0x1234), uint256(0), bytes4(0));
        return kernel.executeFromExecutor(mode, executionData);
    }

    /// @notice Execute a batch of calls via kernel
    function executeBatchViaKernel(Kernel kernel, bytes1 execType, uint256 count) external returns (bytes[] memory) {
        bytes32 mode = bytes32(abi.encodePacked(LibERC7579.CALLTYPE_BATCH, execType, bytes4(0), bytes4(0), bytes22(0)));

        Call[] memory calls = new Call[](count);
        for (uint256 i = 0; i < count; i++) {
            calls[i] = Call({
                to: address(kernel), // Self-call to a view function that doesn't revert
                value: 0,
                data: abi.encodeWithSelector(Kernel.accountId.selector)
            });
        }

        return kernel.executeFromExecutor(mode, abi.encode(calls));
    }

    /// @notice Execute a batch with one reverting call
    function executeBatchWithRevertViaKernel(Kernel kernel, bytes1 execType) external returns (bytes[] memory) {
        bytes32 mode = bytes32(abi.encodePacked(LibERC7579.CALLTYPE_BATCH, execType, bytes4(0), bytes4(0), bytes22(0)));

        Call[] memory calls = new Call[](3);
        calls[0] = Call({to: address(kernel), value: 0, data: abi.encodeWithSelector(Kernel.accountId.selector)});
        // This will revert since it's calling a non-existent function
        calls[1] = Call({to: address(this), value: 0, data: abi.encodeWithSelector(this.forceRevert.selector)});
        calls[2] = Call({to: address(kernel), value: 0, data: abi.encodeWithSelector(Kernel.accountId.selector)});

        return kernel.executeFromExecutor(mode, abi.encode(calls));
    }

    /// @notice Execute a delegatecall via kernel
    function executeDelegatecallViaKernel(Kernel kernel, bytes1 execType, bool shouldRevert)
        external
        returns (bytes[] memory)
    {
        bytes32 mode = bytes32(
            abi.encodePacked(LibERC7579.CALLTYPE_DELEGATECALL, execType, bytes4(0), bytes4(0), bytes22(0))
        );

        bytes memory executionData;
        if (shouldRevert) {
            executionData = abi.encodePacked(address(action), abi.encodeWithSelector(action.doRevertingAction.selector));
        } else {
            executionData = abi.encodePacked(address(action), abi.encodeWithSelector(action.doAction.selector));
        }

        return kernel.executeFromExecutor(mode, executionData);
    }

    /// @notice Helper to force revert
    function forceRevert() external pure {
        revert MockCallee.Haha();
    }
}
