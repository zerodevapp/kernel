// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {IKernelValidator} from "./IKernelValidator.sol";
import {ExecutionDetail, Call} from "../common/Structs.sol";
import {ValidationData, ValidUntil, ValidAfter} from "../common/Types.sol";
import {Operation} from "../common/Enums.sol";
import {UserOperation} from "I4337/interfaces/UserOperation.sol";

interface IKernel {
    // Event declarations
    event Upgraded(address indexed newImplementation);

    event DefaultValidatorChanged(address indexed oldValidator, address indexed newValidator);

    event ExecutionChanged(bytes4 indexed selector, address indexed executor, address indexed validator);

    // Error declarations
    error NotAuthorizedCaller();

    error AlreadyInitialized();

    error NotEntryPoint();

    error DisabledMode();

    error DeprecatedOperation();

    function initialize(IKernelValidator _validator, bytes calldata _data) external payable;

    function upgradeTo(address _newImplementation) external payable;

    function getNonce() external view returns (uint256);

    function getNonce(uint192 key) external view returns (uint256);

    function getDefaultValidator() external view returns (IKernelValidator);

    function getDisabledMode() external view returns (bytes4 disabled);

    function getLastDisabledTime() external view returns (uint48);

    /// @notice Returns the execution details for a specific function signature
    /// @dev This function can be used to get execution details for a specific function signature
    /// @param _selector The function signature
    /// @return ExecutionDetail struct containing the execution details
    function getExecution(bytes4 _selector) external view returns (ExecutionDetail memory);

    /// @notice Changes the execution details for a specific function selector
    /// @dev This function can only be called from the EntryPoint contract, the contract owner, or itself
    /// @param _selector The selector of the function for which execution details are being set
    /// @param _executor The executor to be associated with the function selector
    /// @param _validator The validator contract that will be responsible for validating operations associated with this function selector
    /// @param _validUntil The timestamp until which the execution details are valid
    /// @param _validAfter The timestamp after which the execution details are valid
    function setExecution(
        bytes4 _selector,
        address _executor,
        IKernelValidator _validator,
        ValidUntil _validUntil,
        ValidAfter _validAfter,
        bytes calldata _enableData
    ) external payable;

    function setDefaultValidator(IKernelValidator _defaultValidator, bytes calldata _data) external payable;

    /// @notice Updates the disabled mode
    /// @dev This function can be used to update the disabled mode
    /// @param _disableFlag The new disabled mode
    function disableMode(bytes4 _disableFlag) external payable;

    /// @notice Executes a function call to an external contract
    /// @dev The type of operation (call or delegatecall) is specified as an argument.
    /// @param to The address of the target contract
    /// @param value The amount of Ether to send
    /// @param data The call data to be sent
    /// operation deprecated operation type, usere executeBatch for batch operation
    function execute(address to, uint256 value, bytes memory data, Operation) external payable;

    function executeBatch(Call[] memory calls) external payable;

    function executeDelegateCall(address to, bytes memory data) external payable;

    /// @notice Validates a user operation based on its mode
    /// @dev This function will validate user operation and be called by EntryPoint
    /// @param userOp The user operation to be validated
    /// @param userOpHash The hash of the user operation
    /// @param missingAccountFunds The funds needed to be reimbursed
    /// @return validationData The data used for validation
    function validateUserOp(UserOperation memory userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        payable
        returns (ValidationData validationData);
}
