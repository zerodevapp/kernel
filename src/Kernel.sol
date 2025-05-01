pragma solidity ^0.8.0;

import {IAccount} from "account-abstraction/interfaces/IAccount.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
/*
   Kernel V4
    - native v0.8 support
        - factory update, needs to consider 7702 context
        - eip712 support
    - native 7702 support
    - 7579 account
        - erc7821 execute interface
        - execute with signature
    - enable mode
    - permission validation method
    - signature replay
        - multichain replay
*/
contract Kernel {

    modifier onlyEntryPoint {
        _;
    }
    /// authentication 
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external onlyEntryPoint payable returns (uint256 validationData) {
        return _verifySignature(userOpHash, userOp.signature);
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns(bytes4) {
    }

    function _verifySignature(bytes32 _hash, bytes calldata _signature) internal returns(uint256 validationData){
        return 
    }

    /// execution
    function executeUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) external payable onlyEntryPoint {
    }

    function execute(bytes32 mode, bytes calldata executionData) external {
    }
}

struct Verifier {
    address addr;
}
