// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ValidationId} from "./Types.sol";

/// @notice Thrown when a factory implementation contract has no deployed code.
error ImplementationNotDeployed();

/// @notice Thrown when a module's onInstall callback fails.
error ModuleInstallFailed();

/// @notice Thrown when an unsupported module type is encountered.
error NotImplemented();

/// @notice Thrown when an install-mode signature fails verification.
error InstallSignatureVerificationFailed();

/// @notice Thrown when attempting to set root to an invalid validation type.
error InvalidRootValidation();

/// @notice Thrown when an unsupported call type is used in execution or fallback routing.
error InvalidCallType();

/// @notice Thrown when an unsupported execution type is used.
error InvalidExecType();

/// @notice Thrown when a fallback selector is not installed or not accessible.
error InvalidSelector();

/// @notice Thrown when the caller is not the entry point or the account itself.
error Unauthorized();

/// @notice Thrown when an invalid validation type is specified in a signature or nonce.
error InvalidValidationType();

/// @notice Thrown when attempting to install a validation that already occupies the given ValidationId.
error OccupiedValidationId();

/// @notice Thrown when policies are not uninstalled in reverse order (LIFO).
error InvalidPermissionUninstallOrder();

/// @notice Thrown when removing a target before its scoped execution hook.
error ScopedExecutionHookStillInstalled();

/// @notice Thrown when a scoped-execution-hook scope or target is invalid or not installed.
error InvalidScopedExecutionHookTarget();

/// @notice Thrown when a scoped execution hook is already installed for a target.
error ScopedExecutionHookAlreadyInstalled();

/// @notice Thrown when a permission ID does not match the expected signer or policy configuration.
error InvalidPermissionId();

/// @notice Thrown when a nonce sequence is invalid (out of order or already used).
error InvalidNonce();

/// @notice Thrown when initialization is attempted with an empty package array.
error InvalidInitialization();

/// @notice Thrown when data length does not match the expected format (e.g., selectors not multiple of 4).
error InvalidDataLength();

/// @notice Thrown when attempting to uninstall the current root validation.
error CannotUninstallRoot();

/// @notice Thrown when a signature is invalid or has the wrong number of sub-signatures.
error InvalidSignature();

/// @notice Thrown when a ValidationId is not installed.
/// @param vId The invalid validation identifier.
error InvalidVid(ValidationId vId);

/// @notice Thrown when userOp callData targets a selector not allowed by the validation.
error UnauthorizedCallData();

/// @notice Thrown when a permission install batch is incomplete (signer not yet installed).
error PermissionInstallNotFinished();

/// @notice Thrown when policies and signer within a batch use inconsistent PermissionIds.
error InvalidPermissionInstall();

/// @notice Thrown when a zero-address signer is provided to the ECDSA factory.
error InvalidSigner();

/// @notice Thrown when deploying through a factory that is not approved by the Staker.
error NotApprovedFactory();

/// @notice Thrown when a factory deployment call fails.
error DeployFailed();

/// @notice Thrown when the Staker owner is address(0) during signature verification.
error InvalidOwner();

/// @notice Thrown when the caller is not a registered executor.
error NotExecutor();

/// @notice Thrown when a smart account is already initialized.
/// @param smartAccount The account that was already initialized.
error AlreadyInitialized(address smartAccount);

/// @notice Thrown when a smart account has not been initialized.
/// @param smartAccount The uninitialized account address.
error NotInitialized(address smartAccount);

/// @notice Thrown when an execution target address is invalid (e.g., address(0)).
/// @param target The invalid target address.
error InvalidTargetAddress(address target);

/// @notice Thrown when intersecting validation data with mismatched validity formats (timestamp vs block number).
error ValidityFormatMismatch();

/// @notice Thrown when a non-root validation attempts to grant access to a restricted selector
///         (currently `IAccountExecute.executeUserOp.selector`). Granting `executeUserOp` to a
///         non-root validation would let it invoke arbitrary kernel functions via the inner
///         delegatecall, bypassing the selector allow-list.
error InvalidSelectorGrant();

/// @notice Thrown when a fallback selector install is attempted with the zero address as target.
///         Downstream dispatch rejects zero-target with `InvalidSelector`, so allowing the write
///         would silently drop the caller's intent; this enforces the invariant at the install boundary.
error InvalidSelectorTarget();
