pragma solidity ^0.8.0;

import "../interfaces/IValidator.sol";
import "./Enum.sol";
import "./Types.sol";

// Defining a struct for execution details
struct ExecutionDetail {
    ValidAfter validAfter; // Until what time is this execution valid
    ValidUntil validUntil; // After what time is this execution valid
    address executor; // Who is the executor of this execution
    IKernelValidator validator; // The validator for this execution
}

// Defining a struct for wallet kernel storage
struct WalletKernelStorage {
    bytes32 __deprecated; // A deprecated field
    bytes4 disabledMode; // Mode which is currently disabled
    uint48 lastDisabledTime; // Last time when a mode was disabled
    IKernelValidator defaultValidator; // Default validator for the wallet
    mapping(bytes4 => ExecutionDetail) execution; // Mapping of function selectors to execution details
}

// Param Rule for session key
struct ParamRule {
    uint256 offset;
    ParamCondition condition;
    bytes32 param;
}

struct Permission {
    address target;
    uint256 valueLimit;
    bytes4 sig;
    ParamRule[] rules;
    Operation operation;
}

struct SessionData {
    bytes32 merkleRoot;
    ValidAfter validAfter;
    ValidUntil validUntil;
    address paymaster; // address(0) means accept userOp without paymaster, address(1) means reject userOp with paymaster, other address means accept userOp with paymaster with the address
    bool enabled;
}
