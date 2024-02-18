// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {PackedUserOperation} from "./PackedUserOperation.sol";
import {EncodedModuleTypes} from "../utils/ModuleTypeLib.sol";

uint256 constant VALIDATION_SUCCESS = 0;
uint256 constant VALIDATION_FAILED = 1;

uint256 constant MODULE_TYPE_VALIDATOR = 1;
uint256 constant MODULE_TYPE_EXECUTOR = 2;
uint256 constant MODULE_TYPE_FALLBACK = 3;
uint256 constant MODULE_TYPE_HOOK = 4;

interface IModule {
    error AlreadyInitialized(address smartAccount);
    error NotInitialized(address smartAccount);

    /**
     * @dev This function is called by the smart account during installation of the module
     * @param data arbitrary data that may be required on the module during `onInstall`
     * initialization
     *
     * MUST revert on error (i.e. if module is already enabled)
     */
    function onInstall(bytes calldata data) external;

    /**
     * @dev This function is called by the smart account during uninstallation of the module
     * @param data arbitrary data that may be required on the module during `onUninstall`
     * de-initialization
     *
     * MUST revert on error
     */
    function onUninstall(bytes calldata data) external;

    /**
     * @dev Returns boolean value if module is a certain type
     * @param typeID the module type ID according the ERC-7579 spec
     *
     * MUST return true if the module is of the given type and false otherwise
     */
    function isModuleType(uint256 typeID) external view returns (bool);

    /**
     * @dev Returns bit-encoded integer of the different typeIds of the module
     *
     * MUST return all the bit-encoded typeIds of the module
     */
    function getModuleTypes() external view returns (EncodedModuleTypes);

    /**
     * @dev Returns if the module was already initialized for a provided smartaccount
     */
    function isInitialized(address smartAccount) external view returns (bool);
}

interface IValidator is IModule {
    error InvalidTargetAddress(address target);

    /**
     * @dev Validates a transaction on behalf of the account.
     *         This function is intended to be called by the MSA during the ERC-4337 validaton phase
     *         Note: solely relying on bytes32 hash and signature is not suffcient for some
     * validation implementations (i.e. SessionKeys often need access to userOp.calldata)
     * @param userOp The user operation to be validated. The userOp MUST NOT contain any metadata.
     * The MSA MUST clean up the userOp before sending it to the validator.
     * @param userOpHash The hash of the user operation to be validated
     * @return return value according to ERC-4337
     */
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external returns (uint256);

    /**
     * Validator can be used for ERC-1271 validation
     */
    function isValidSignatureWithSender(address sender, bytes32 hash, bytes calldata data)
        external
        view
        returns (bytes4);
}

interface IExecutor is IModule {}

interface IHook is IModule {
    function preCheck(address msgSender, bytes calldata msgData) external returns (bytes memory hookData);
    function postCheck(bytes calldata hookData) external returns (bool success);
}

interface IFallback is IModule {}
