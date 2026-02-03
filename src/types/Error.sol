pragma solidity ^0.8.0;

import {ValidationId} from "./Types.sol";

error ModuleInstallFailed();
error ModuleUninstallFailed();

error InvalidValidator();

error NotImplemented();

error NotInstalled();

error InstallSignatureVerificationFailed();

error InvalidRootValidation();
error InvalidCallType();
error InvalidExecType();

error InvalidSelector();
error InvalidEnableSignature();

error Unauthorized();

error InvalidValidationType();
error OccupiedValidationId();

error InvalidPermissionUninstallOrder();
error InvalidPermissionId();
error InvalidNonce();
error InvalidInitialization();
error InvalidDataLength();
error InvalidSignature();
error InvalidVid(ValidationId vId);

error UnauthorizedCallData();
