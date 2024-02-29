pragma solidity ^0.8.0;

import {UserOperation} from "I4337/interfaces/UserOperation.sol";
import {ValidationData, ValidAfter, ValidUntil} from "src/common/Types.sol";
import {SIG_VALIDATION_FAILED} from "src/common/Constants.sol";
import {IKernelValidator} from "src/interfaces/IKernelValidator.sol";
import {ISigner} from "./ISigner.sol";
import {IPolicy} from "./IPolicy.sol";
import {_intersectValidationData} from "src/utils/KernelHelper.sol";
import {PolicyConfig, PolicyConfigLib, toFlag, MAX_FLAG} from "./PolicyConfig.sol";
import "forge-std/console.sol";

struct Permission {
    uint128 nonce;
    bytes12 flag; // flag represents what permission can do
    ISigner signer;
    PolicyConfig firstPolicy;
    ValidAfter validAfter;
    ValidUntil validUntil;
}

struct Nonce {
    uint128 lastNonce;
    uint128 revoked;
}

/// @title ModularPermissionValidator
/// @notice Validator that allows to register and revoke permissions
/// @dev modular architecture to allow composable permission system
contract ModularPermissionValidator is IKernelValidator {
    mapping(address => bytes32) public priorityPermission;
    mapping(bytes32 permissionId => mapping(address kernel => Permission)) public permissions;
    mapping(bytes32 permissionId => mapping(PolicyConfig policy => mapping(address kernel => PolicyConfig))) public
        nextPolicy;
    mapping(address kernel => Nonce) public nonces;

    event PermissionRegistered(address kernel, bytes32 permissionId);
    event PermissionRevoked(address kernel, bytes32 permissionId);
    event NonceRevoked(address kernel, uint256 nonce);

    function getPermissionId(
        bytes12 flag,
        ISigner signer,
        ValidAfter validAfter,
        ValidUntil validUntil,
        PolicyConfig[] calldata _policyConfig,
        bytes calldata signerData,
        bytes[] calldata policyData
    ) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                flag,
                signer,
                ValidAfter.unwrap(validAfter),
                ValidUntil.unwrap(validUntil),
                _policyConfig,
                signerData,
                policyData
            )
        );
    }

    function parseData(bytes calldata data)
        public
        pure
        returns (
            uint128 nonce,
            bytes12 flag,
            ISigner signer,
            ValidAfter validAfter,
            ValidUntil validUntil,
            PolicyConfig[] calldata policies,
            bytes calldata signerData,
            bytes[] calldata policyData
        )
    {
        nonce = uint128(bytes16(data[0:16]));
        flag = bytes12(data[16:28]);
        validAfter = ValidAfter.wrap(uint48(bytes6(data[28:34])));
        validUntil = ValidUntil.wrap(uint48(bytes6(data[34:40])));
        signer = ISigner(address(bytes20(data[40:60])));
        assembly {
            let offset := add(data.offset, 60)
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
            bytes12 flag,
            ISigner signer,
            ValidAfter validAfter,
            ValidUntil validUntil,
            PolicyConfig[] calldata policies,
            bytes calldata signerData,
            bytes[] calldata policyData
        ) = parseData(data);
        registerPermission(nonce, flag, signer, validAfter, validUntil, policies, signerData, policyData);
    }

    function registerPermission(
        uint128 nonce,
        bytes12 flag,
        ISigner signer,
        ValidAfter validAfter,
        ValidUntil validUntil,
        PolicyConfig[] calldata policy,
        bytes calldata signerData,
        bytes[] calldata policyData
    ) public payable {
        require(flag != toFlag(0), "flag should not be empty");
        require(
            nonce == nonces[msg.sender].lastNonce || nonce == nonces[msg.sender].lastNonce + 1, "nonce should be next"
        );
        nonces[msg.sender].lastNonce++;
        bytes32 permissionId = getPermissionId(flag, signer, validAfter, validUntil, policy, signerData, policyData);
        if (flag == MAX_FLAG) {
            priorityPermission[msg.sender] = permissionId;
        }

        bytes12 maxFlag = flag;
        for (uint256 i = 0; i < policy.length; i++) {
            //TODO make sure address of the policy is sorted
            PolicyConfigLib.getAddress(policy[i]).registerPolicy(msg.sender, permissionId, policyData[i]);
            // NOTE: flag for policy is inverted version of flag for permission;
            bytes12 currentFlag = PolicyConfigLib.getFlags(policy[i]);
            // turn off flags that are used,
            // meaning that remaining maxFlag will indicate the permissions that are not used on this permission
            maxFlag = currentFlag & maxFlag;
        }
        signer.registerSigner(msg.sender, permissionId, signerData);

        PolicyConfig firstPolicy = policy[0]; // NOTE : policy should not be empty array
        require(maxFlag == bytes12(0), "error : permission flag exceeds policy flag");
        permissions[permissionId][msg.sender] = Permission(nonce, flag, signer, firstPolicy, validAfter, validUntil);
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
        permissions[permissionId][msg.sender].flag = toFlag(0); // NOTE: making flag == 0 makes it invalid
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
            permissions[permissionId][msg.sender].flag & toFlag(1) == toFlag(0)
                || nonces[msg.sender].revoked > permissions[permissionId][msg.sender].nonce
        ) {
            return SIG_VALIDATION_FAILED;
        }
        Permission memory permission = permissions[permissionId][msg.sender];
        PolicyConfig policy = permission.firstPolicy;
        uint256 cursor = 32;
        while (address(PolicyConfigLib.getAddress(policy)) != address(0)) {
            if (PolicyConfigLib.skipOnValidateUserOp(policy)) {
                policy = nextPolicy[permissionId][policy][msg.sender];
                continue;
            }
            bytes calldata policyData;
            if (
                _userOp.signature.length >= cursor + 52
                    && address(bytes20(_userOp.signature[cursor:cursor + 20]))
                        == address(PolicyConfigLib.getAddress(policy))
            ) {
                // only when policy address is same as the one in signature
                uint256 length = uint256(bytes32(_userOp.signature[cursor + 20:cursor + 52]));
                require(_userOp.signature.length >= cursor + 52 + length, "policyData length exceeds signature length");
                policyData = _userOp.signature[cursor + 52:cursor + 52 + length]; // [policyAddress, policyDataLength, policyData]
                cursor += 52 + length;
            } else {
                policyData = _userOp.signature[cursor:cursor];
            }
            ValidationData policyValidation =
                PolicyConfigLib.getAddress(policy).checkUserOpPolicy(msg.sender, permissionId, _userOp, policyData);
            validationData = _intersectValidationData(validationData, policyValidation);
            policy = nextPolicy[permissionId][policy][msg.sender];
        }
        ValidationData signatureValidation =
            permission.signer.validateUserOp(msg.sender, permissionId, _userOpHash, _userOp.signature[cursor:]);
        validationData = _intersectValidationData(validationData, signatureValidation);
    }

    function validCaller(address caller, bytes calldata data) external view override returns (bool) {
        revert("not implemented");
    }

    struct ValidationSigMemory {
        address caller;
        bytes32 permissionId;
        bytes32 rawHash;
        uint256 cursor;
        PolicyConfig policy;
    }

    function validateSignature(bytes32 hash, bytes calldata signature)
        external
        view
        override
        returns (ValidationData validationData)
    {
        ValidationSigMemory memory sigMemory;
        sigMemory.permissionId = bytes32(signature[0:32]);
        if (
            nonces[msg.sender].revoked > permissions[sigMemory.permissionId][msg.sender].nonce
                || permissions[sigMemory.permissionId][msg.sender].flag & toFlag(2) == toFlag(0)
        ) {
            return SIG_VALIDATION_FAILED;
        }
        Permission memory permission = permissions[sigMemory.permissionId][msg.sender];
        // signature should be packed with
        // (permissionId, [proof || signature])
        // (permissionId, [ (policyAddress) + (policyProof) || signature]
        bytes calldata proofAndSignature; //) = abi.decode(signature[32:], (bytes, bytes));
        assembly {
            proofAndSignature.offset := add(signature.offset, 32)
            proofAndSignature.length := sub(signature.length, 32)
        }

        sigMemory.cursor = 0;
        sigMemory.policy = permission.firstPolicy;
        sigMemory.caller = address(bytes20(msg.data[msg.data.length - 20:]));
        sigMemory.rawHash = bytes32(msg.data[msg.data.length - 52:msg.data.length - 20]);
        while (address(PolicyConfigLib.getAddress(sigMemory.policy)) != address(0)) {
            if (PolicyConfigLib.skipOnValidateSignature(sigMemory.policy)) {
                sigMemory.policy = nextPolicy[sigMemory.permissionId][sigMemory.policy][msg.sender];
                continue;
            }
            bytes calldata policyData;
            if (
                address(bytes20(proofAndSignature[sigMemory.cursor:sigMemory.cursor + 20]))
                    == address(PolicyConfigLib.getAddress(sigMemory.policy))
            ) {
                // only when policy address is same as the one in signature
                uint256 length = uint256(bytes32(proofAndSignature[sigMemory.cursor + 20:sigMemory.cursor + 52]));
                policyData = proofAndSignature[sigMemory.cursor + 52:]; // [policyAddress, policyDataLength, policyData]
                sigMemory.cursor += 52 + length;
            } else {
                policyData = proofAndSignature[sigMemory.cursor:sigMemory.cursor];
                // not move cursor here
            }
            ValidationData policyValidation = PolicyConfigLib.getAddress(sigMemory.policy).validateSignature(
                msg.sender, sigMemory.caller, sigMemory.permissionId, hash, sigMemory.rawHash, policyData
            );
            validationData = _intersectValidationData(validationData, policyValidation);
            sigMemory.policy = nextPolicy[sigMemory.permissionId][sigMemory.policy][msg.sender];
        }
        ValidationData signatureValidation = permission.signer.validateSignature(
            msg.sender, sigMemory.permissionId, hash, proofAndSignature[sigMemory.cursor:]
        );
        validationData = _intersectValidationData(validationData, signatureValidation);
    }
}
