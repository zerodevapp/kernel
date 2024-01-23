pragma solidity ^0.8.0;

import {UserOperation} from "I4337/interfaces/UserOperation.sol";
import {ValidationData} from "src/common/Types.sol";
import {SIG_VALIDATION_FAILED} from "src/common/Constants.sol";
import {IKernelValidator} from "src/interfaces/IKernelValidator.sol";
import {ISigner} from "./ISigner.sol";
import {IPolicy} from "./IPolicy.sol";

// permission should handle the flag of following
// - check if permission is allowed to sign arbitrary signature, notice this is view so this cannot guarantee if signature is used
// - check if permission is allowed to call function directly
// - if aggregator address is returned from policy.validatePolicy, DO NOT invoke signer, delegate signer role to aggregator instead => CHECK is this safe???
//   - TODO : test this is aggregator can be setup as signer
// - if no policy is defined, should bypass policy
// - if no signer is defined, revert
// - if nonce is revoked, and policy is not 0, revert
//   note that nonce revokation revokes all permissions that has lower nonce than revoked nonce
// - if nonce is revoked, and policy is 0, do not revert, this will act as sudo permission
//   note that permissionId revokation should be considered revoked
// Policy should handle followings
// - check if permission is allowed to sign userOp with/without the gas spent by user
// - check if permission is allowed to sign given signature
// - check if permission is allowed to call function directly
// - return aggregator address if needed
// Signer should handle followings
// - check if userOpHash is signed
// - check msgHash is signed
// - note that checking signature prefix, checking replay attack should not be handled by signer
//   - this remains responsibility of app / kernel
struct Permission {
    uint128 nonce;
    uint128 status; // status == 0 => revoked, status == 1 => active
    uint48 validAfter;
    uint48 validUntil;
    ISigner signer;
    IPolicy firstPolicy;
}

struct Nonce {
    uint128 latest;
    uint128 revoked;
}

/*
eth_requestPermissions
Request
{
    "type": "call",
    "data" : [{
        "to": "<address to call>",
        "amount": "<amount of ether to send>",
        "data" : "<data to send>",
    }],
    "gas" : "sponsored | not sponsored | max priority fee limit, preVerificationGas limit"
    "validUntil" : "<timestamp>",
    "validAfter" : "<timestamp>",
    "signer" : {
        "address" : "<signer contract address>",
        "data" : "<signer initialization data>"
    }
}
{
    "type" : "erc20",
    "data" : [{
        "amount" : "<amount of token to allow>",
    }]
    "gas" : "sponsored | not sponsored | max priority fee limit, preVerificationGas limit"
    "validUntil" : "<timestamp>",
    "validAfter" : "<timestamp>",
    "signer" : {
        "address" : "<signer contract address>",
        "data" : "<signer initialization data>"
    }
}
Response
{
    "permissionId": "<permissionId>",
    "nonce": "<nonce>",
    "validAfter": "<validAfter>",
    "validUntil": "<validUntil>",

}
eth_requestPolicyProof
Request
{
    "permissionId": "<permissionId>",
    "userOperation": "<userOperation>",
}
Response
{
    "proof": "<proof>"
}
*/

import "forge-std/console.sol";

contract ModularPermissionValidator is IKernelValidator {
    mapping(bytes32 permissionId => mapping(address kernel => Permission)) public permissions;
    mapping(bytes32 permissionId => mapping(IPolicy policy => mapping(address kernel => IPolicy))) public nextPolicy;
    mapping(address kernel => Nonce) public nonces;

    event PermissionRegistered(address kernel, bytes32 permissionId);
    event PermissionRevoked(address kernel, bytes32 permissionId);
    event NonceRevoked(address kernel, uint256 nonce);

    function getPermissionId(
        uint256 nonce,
        uint48 validAfter,
        uint48 validUntil,
        ISigner signer,
        IPolicy[] calldata _permissions,
        bytes calldata signerData,
        bytes[] calldata permissionData
    ) external pure returns (bytes32) {
        return keccak256(abi.encode(nonce, validAfter, validUntil, signer, _permissions, signerData, permissionData));
    }

    function parseData(bytes calldata data)
        public
        view
        returns (
            uint128 nonce,
            uint48 validAfter,
            uint48 validUntil,
            ISigner signer,
            IPolicy[] calldata policies,
            bytes calldata signerData,
            bytes[] calldata policyData
        )
    {
        nonce = uint128(bytes16(data[0:16]));
        validAfter = uint48(bytes6(data[16:22]));
        validUntil = uint48(bytes6(data[22:28]));
        signer = ISigner(address(bytes20(data[28:48])));
        assembly {
            let offset := add(data.offset, 48)
            policies.offset := add(add(offset, 32), calldataload(offset))
            policies.length := calldataload(sub(policies.offset, 32))
            signerData.offset := add(add(offset, 32), calldataload(add(offset, 32)))
            signerData.length := calldataload(sub(signerData.offset, 32))
            policyData.offset := add(add(offset, 32), calldataload(add(offset, 64)))
            policyData.length := calldataload(sub(policyData.offset, 32))
        }
    }

    function enable(bytes calldata data) external payable {
        (
            uint128 nonce,
            uint48 validAfter,
            uint48 validUntil,
            ISigner signer,
            IPolicy[] calldata policies,
            bytes calldata signerData,
            bytes[] calldata policyData
        ) = parseData(data);
        registerPermission(nonce, validAfter, validUntil, signer, policies, signerData, policyData);
    }

    function registerPermission(
        uint128 nonce,
        uint48 validAfter,
        uint48 validUntil,
        ISigner signer,
        IPolicy[] calldata policy,
        bytes calldata signerData,
        bytes[] calldata policyData
    ) public payable {
        bytes32 permissionId =
            keccak256(abi.encode(msg.sender, nonce, validAfter, validUntil, signer, policy, signerData, policyData));

        for (uint256 i = 0; i < policy.length; i++) {
            policy[i].registerPolicy(msg.sender, permissionId, policyData[i]);
        }
        signer.registerSigner(msg.sender, permissionId, signerData);

        IPolicy firstPolicy = policy[0]; // NOTE : policy should not be empty array
        permissions[permissionId][msg.sender] = Permission(nonce, 1, validAfter, validUntil, signer, firstPolicy);
        for (uint256 i = 1; i < policy.length; i++) {
            nextPolicy[permissionId][policy[i - 1]][msg.sender] = policy[i];
        }
        emit PermissionRegistered(msg.sender, permissionId);
    }

    function disable(bytes calldata data) external payable {
        if (data.length == 32) {
            revokePermission(bytes32(data));
        } else {
            revokePermission(uint128(bytes16(data)));
        }
    }

    function revokePermission(bytes32 permissionId) public payable {
        permissions[permissionId][msg.sender].status = 0;
        emit PermissionRevoked(msg.sender, permissionId);
    }

    function revokePermission(uint128 nonce) public payable {
        nonces[msg.sender].revoked = nonce;
        emit NonceRevoked(msg.sender, nonce);
    }

    function validateUserOp(UserOperation calldata _userOp, bytes32 _userOpHash, uint256)
        external
        payable
        returns (ValidationData validationData)
    {
        require(_userOp.sender == msg.sender, "sender must be msg.sender");
        bytes32 permissionId = bytes32(_userOp.signature[0:32]);
        if (
            address(permissions[permissionId][msg.sender].firstPolicy) != address(0)
                && permissions[permissionId][msg.sender].nonce < nonces[msg.sender].revoked
        ) {
            return SIG_VALIDATION_FAILED;
        }
        Permission memory permission = permissions[permissionId][msg.sender];
        IPolicy policy = permission.firstPolicy;
        uint256 cursor = 32;
        while (address(policy) != address(0)) {
            (ValidationData policyValidation, uint256 sigOffset) =
                policy.validatePolicy(msg.sender, permissionId, _userOp, _userOp.signature[cursor:]);
            // DO validationdata merge
            policy = nextPolicy[permissionId][policy][msg.sender];
            cursor += sigOffset;
        }
        ValidationData signatureValidation =
            permission.signer.validateUserOp(msg.sender, permissionId, _userOpHash, _userOp.signature[cursor:]);
        // DO validationdata merge
        return signatureValidation;
    }

    function validCaller(address caller, bytes calldata data)
        external
        pure // TODO: this will turn non-view from 2.4
        override
        returns (bool)
    {
        revert("not implemented");
    }

    struct ValidationSigMemory {
        bytes32 permissionId;
        uint256 cursor;
        IPolicy policy;
    }

    function validateSignature(bytes32 hash, bytes calldata signature)
        external
        view
        override
        returns (ValidationData)
    {
        ValidationSigMemory memory sigMemory;
        sigMemory.permissionId = bytes32(signature[0:32]);
        Permission memory permission = permissions[sigMemory.permissionId][msg.sender];
        // signature should be packed with
        // (permissionId, rawMessage, [proof || signature])

        bytes calldata proofAndSignature; //) = abi.decode(signature[32:], (bytes, bytes));
        {
            bytes calldata rawMessage;
            assembly {
                rawMessage.offset := add(signature.offset, calldataload(add(signature.offset, 32)))
                rawMessage.length := calldataload(rawMessage.offset)
                proofAndSignature.offset := add(signature.offset, calldataload(add(signature.offset, 64)))
                proofAndSignature.length := calldataload(proofAndSignature.offset)
            }
            require(hash == keccak256(rawMessage));
        }

        sigMemory.cursor = 0;
        sigMemory.policy = permission.firstPolicy;
        while (address(sigMemory.policy) != address(0)) {
            (ValidationData policyValidation, uint256 sigOffset) = sigMemory.policy.validateSignature(
                msg.sender, msg.sender, sigMemory.permissionId, hash, proofAndSignature[sigMemory.cursor:]
            );
            // DO validationdata merge
            sigMemory.policy = nextPolicy[sigMemory.permissionId][sigMemory.policy][msg.sender];
            sigMemory.cursor += sigOffset;
        }
        ValidationData signatureValidation = permission.signer.validateSignature(
            msg.sender, sigMemory.permissionId, hash, proofAndSignature[sigMemory.cursor:]
        );
        // DO validationdata merge
        return signatureValidation;
    }
}
