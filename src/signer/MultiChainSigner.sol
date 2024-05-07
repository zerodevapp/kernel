// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {ECDSA} from "solady/utils/ECDSA.sol";
import {MerkleProofLib} from "solady/utils/MerkleProofLib.sol";
import {ISigner} from "../interfaces/IERC7579Modules.sol";
import {SignerBase} from "../sdk/moduleBase/SignerBase.sol";
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

contract MultiChainSigner is SignerBase {
    mapping(address => uint256) public usedIds;
    mapping(bytes32 id => mapping(address wallet => address)) public signer;

    event SignerRegistered(address indexed kernel, bytes32 indexed id, address indexed owner);

    error NoSignerRegistered();

    function isInitialized(address wallet) external view override returns (bool) {
        return usedIds[wallet] > 0;
    }

    function _signerOninstall(bytes32 id, bytes calldata _data) internal override {
        if (signer[id][msg.sender] == address(0)) {
            usedIds[msg.sender]++;
        }
        signer[id][msg.sender] = address(bytes20(_data[0:20]));
        emit SignerRegistered(msg.sender, id, address(bytes20(_data[0:20])));
    }

    function _signerOnUninstall(bytes32 id, bytes calldata) internal override {
        if (signer[id][msg.sender] == address(0)) {
            revert NoSignerRegistered();
        }
        delete signer[id][msg.sender];
        usedIds[msg.sender]--;
    }

    function checkUserOpSignature(bytes32 id, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        payable
        override
        returns (uint256)
    {
        bytes calldata sig = userOp.signature;
        address owner = signer[id][msg.sender];
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

    function checkSignature(bytes32 id, address sender, bytes32 hash, bytes calldata sig)
        external
        view
        override
        returns (bytes4)
    {
        address owner = signer[id][msg.sender];
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
}
