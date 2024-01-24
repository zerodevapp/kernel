pragma solidity ^0.8.0;

import {UserOperation} from "I4337/interfaces/UserOperation.sol";
import {ValidationData} from "src/common/Types.sol";
import {SIG_VALIDATION_FAILED} from "src/common/Constants.sol";
import {IKernelValidator} from "src/interfaces/IKernelValidator.sol";
import {ISigner} from "./ISigner.sol";
import {IPolicy} from "./IPolicy.sol";
import {_intersectValidationData} from "src/utils/KernelHelper.sol";

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
/// @title ModularPermissionValidator
/// @notice ModularPermissionValidator is a Kernel validator that allows to register and revoke permissions
/// @dev modular architecture to allow composable permission system

contract ModularPermissionValidator is IKernelValidator {
    mapping(bytes32 permissionId => mapping(address kernel => Permission)) public permissions;
    mapping(bytes32 permissionId => mapping(IPolicy policy => mapping(address kernel => IPolicy))) public nextPolicy;
    mapping(address kernel => Nonce) public nonces;

    event PermissionRegistered(address kernel, bytes32 permissionId);
    event PermissionRevoked(address kernel, bytes32 permissionId);
    event NonceRevoked(address kernel, uint256 nonce);

    function getPermissionId(
        address kernel,
        uint128 nonce,
        uint48 validAfter,
        uint48 validUntil,
        ISigner signer,
        IPolicy[] calldata _permissions,
        bytes calldata signerData,
        bytes[] calldata permissionData
    ) public pure returns (bytes32) {
        return keccak256(
            abi.encode(kernel, nonce, validAfter, validUntil, signer, _permissions, signerData, permissionData)
        );
    }

    function parseData(bytes calldata data)
        public
        pure
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
            getPermissionId(msg.sender, nonce, validAfter, validUntil, signer, policy, signerData, policyData);

        for (uint256 i = 0; i < policy.length; i++) {
            policy[i].registerPolicy(msg.sender, permissionId, policyData[i]);
        }
        signer.registerSigner(msg.sender, permissionId, signerData);

        IPolicy firstPolicy = policy[0]; // NOTE : policy should not be empty array
        permissions[permissionId][msg.sender] = Permission(nonce, 1, validAfter, validUntil, signer, firstPolicy);
        for (uint256 i = 1; i < policy.length; i++) {
            // TODO: remove infinite loop by forcing incremental address
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
            validationData = _intersectValidationData(validationData, policyValidation);
            policy = nextPolicy[permissionId][policy][msg.sender];
            cursor += sigOffset;
        }
        ValidationData signatureValidation =
            permission.signer.validateUserOp(msg.sender, permissionId, _userOpHash, _userOp.signature[cursor:]);
        // DO validationdata merge
        validationData = _intersectValidationData(validationData, signatureValidation);
    }

    function validCaller(address caller, bytes calldata data)
        external
        payable // TODO: this will turn non-view from 2.4
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
        returns (ValidationData validationData)
    {
        ValidationSigMemory memory sigMemory;
        sigMemory.permissionId = bytes32(signature[0:32]);
        Permission memory permission = permissions[sigMemory.permissionId][msg.sender];
        // signature should be packed with
        // (permissionId, [proof || signature])
        bytes calldata proofAndSignature; //) = abi.decode(signature[32:], (bytes, bytes));
        assembly {
            proofAndSignature.offset := add(signature.offset, calldataload(add(signature.offset, 32)))
            proofAndSignature.length := calldataload(sub(proofAndSignature.offset, 32))
        }

        sigMemory.cursor = 0;
        sigMemory.policy = permission.firstPolicy;
        while (address(sigMemory.policy) != address(0)) {
            (ValidationData policyValidation, uint256 sigOffset) = sigMemory.policy.validateSignature(
                msg.sender,
                address(bytes20(msg.data[msg.data.length - 20:])),
                sigMemory.permissionId,
                hash,
                proofAndSignature[sigMemory.cursor:]
            );
            validationData = _intersectValidationData(validationData, policyValidation);
            // DO validationdata merge
            sigMemory.policy = nextPolicy[sigMemory.permissionId][sigMemory.policy][msg.sender];
            sigMemory.cursor += sigOffset;
        }
        ValidationData signatureValidation = permission.signer.validateSignature(
            msg.sender, sigMemory.permissionId, hash, proofAndSignature[sigMemory.cursor:]
        );
        // DO validationdata merge
        validationData = _intersectValidationData(validationData, signatureValidation);
    }
}
