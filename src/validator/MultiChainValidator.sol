// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {ECDSA} from "solady/utils/ECDSA.sol";
import {MerkleProofLib} from "solady/utils/MerkleProofLib.sol";
import {IValidator, IHook} from "../interfaces/IERC7579Modules.sol";
import {PackedUserOperation} from "../interfaces/PackedUserOperation.sol";
import {
    SIG_VALIDATION_SUCCESS_UINT,
    SIG_VALIDATION_FAILED_UINT,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_HOOK,
    ERC1271_MAGICVALUE,
    ERC1271_INVALID
} from "../types/Constants.sol";

struct ECDSAValidatorStorage {
    address owner;
}

bytes constant DUMMY_ECDSA_SIG =
    hex"fffffffffffffffffffffffffffffff0000000000000000000000000000000007aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c";

contract MultiChainValidator is IValidator, IHook {
    event OwnerRegistered(address indexed kernel, address indexed owner);

    mapping(address => ECDSAValidatorStorage) public ecdsaValidatorStorage;

    function onInstall(bytes calldata _data) external payable override {
        address owner = address(bytes20(_data[0:20]));
        ecdsaValidatorStorage[msg.sender].owner = owner;
        emit OwnerRegistered(msg.sender, owner);
    }

    function onUninstall(bytes calldata) external payable override {
        if (!_isInitialized(msg.sender)) revert NotInitialized(msg.sender);
        delete ecdsaValidatorStorage[msg.sender];
    }

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == MODULE_TYPE_VALIDATOR || typeID == MODULE_TYPE_HOOK;
    }

    function isInitialized(address smartAccount) external view override returns (bool) {
        return _isInitialized(smartAccount);
    }

    function _isInitialized(address smartAccount) internal view returns (bool) {
        return ecdsaValidatorStorage[smartAccount].owner != address(0);
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        override
        returns (uint256)
    {
        bytes calldata sig = userOp.signature;
        address owner = ecdsaValidatorStorage[msg.sender].owner;
        if (sig.length == 65) {
            // simple ecdsa verification
            if (owner == ECDSA.recover(userOpHash, sig)) {
                return SIG_VALIDATION_SUCCESS_UINT;
            }
            bytes32 ethHash = ECDSA.toEthSignedMessageHash(userOpHash);
            address recovered = ECDSA.recover(ethHash, sig);
            if (owner != recovered) {
                return SIG_VALIDATION_FAILED_UINT;
            }
            return SIG_VALIDATION_SUCCESS_UINT;
        }
        bytes memory ecdsaSig = sig[0:65];
        bytes32 merkleRoot = bytes32(sig[65:97]);
        // if the signature is a dummy signature, then use dummyUserOpHash instead of real userOpHash
        if (keccak256(ecdsaSig) == keccak256(DUMMY_ECDSA_SIG)) {
            (bytes32 dummyUserOpHash, bytes32[] memory proof) = abi.decode(sig[97:], (bytes32, bytes32[]));
            require(MerkleProofLib.verify(proof, merkleRoot, dummyUserOpHash), "hash is not in proof");
            // otherwise, use real userOpHash
        } else {
            bytes32[] memory proof = abi.decode(sig[97:], (bytes32[]));
            require(MerkleProofLib.verify(proof, merkleRoot, userOpHash), "hash is not in proof");
        }
        // simple ecdsa verification
        if (owner == ECDSA.recover(merkleRoot, ecdsaSig)) {
            return SIG_VALIDATION_SUCCESS_UINT;
        }
        bytes32 ethRoot = ECDSA.toEthSignedMessageHash(merkleRoot);
        address merkleRecovered = ECDSA.recover(ethRoot, ecdsaSig);
        if (owner != merkleRecovered) {
            return SIG_VALIDATION_FAILED_UINT;
        }
        return SIG_VALIDATION_SUCCESS_UINT;
    }

    function isValidSignatureWithSender(address, bytes32 hash, bytes calldata sig)
        external
        view
        override
        returns (bytes4)
    {
        address owner = ecdsaValidatorStorage[msg.sender].owner;
        if (sig.length == 65) {
            // simple ecdsa verification
            if (owner == ECDSA.recover(hash, sig)) {
                return ERC1271_MAGICVALUE;
            }
            bytes32 ethHash = ECDSA.toEthSignedMessageHash(hash);
            address recovered = ECDSA.recover(ethHash, sig);
            if (owner != recovered) {
                return ERC1271_INVALID;
            }
            return ERC1271_MAGICVALUE;
        }
        bytes memory ecdsaSig = sig[0:65];
        bytes32 merkleRoot = bytes32(sig[65:97]);
        bytes32[] memory proof = abi.decode(sig[97:], (bytes32[]));
        require(MerkleProofLib.verify(proof, merkleRoot, hash), "hash is not in proof");
        // simple ecdsa verification
        if (owner == ECDSA.recover(merkleRoot, ecdsaSig)) {
            return ERC1271_MAGICVALUE;
        }
        bytes32 ethRoot = ECDSA.toEthSignedMessageHash(merkleRoot);
        address merkleRecovered = ECDSA.recover(ethRoot, ecdsaSig);
        if (owner != merkleRecovered) {
            return ERC1271_INVALID;
        }
        return ERC1271_MAGICVALUE;
    }

    function preCheck(address msgSender, uint256 value, bytes calldata)
        external
        payable
        override
        returns (bytes memory)
    {
        require(msgSender == ecdsaValidatorStorage[msg.sender].owner, "ECDSAValidator: sender is not owner");
        return hex"";
    }

    function postCheck(bytes calldata hookData) external payable override {}
}
