// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "./IValidator.sol";
import "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import "src/utils/KernelHelper.sol";
import "src/utils/SignatureDecoder.sol";
import "src/interfaces/IMultiSigAddressBook.sol";
import "forge-std/Test.sol";

struct MultiSigValidatorStorage {
    mapping(address => bool) isOwner;
    uint256 threshold;
    uint256 ownerCount;
}

contract MultiSigValidator is IKernelValidator, SignatureDecoder, Test {
    event OwnerAdded(address indexed kernel, address indexed owner);
    event OwnerRemoved(address indexed kernel, address indexed owner);
    event ThresholdChanged(address indexed kernel, uint256 indexed threshold);

    mapping(address => MultiSigValidatorStorage)
        public multiSigValidatorStorage;

    function disable(bytes calldata _data) external override {
        address[] memory owners = abi.decode(_data, (address[]));
        for (uint256 i = 0; i < owners.length; i++) {
            multiSigValidatorStorage[msg.sender].isOwner[owners[i]] = false;
            emit OwnerRemoved(msg.sender, owners[i]);
        }
    }

    function enable(bytes calldata _data) external override {
        address addressBook = address(bytes20(_data));
        address[] memory owners = IMultiSigAddressBook(addressBook).getOwners();
        uint256 threshold = IMultiSigAddressBook(addressBook).getThreshold();
        for (uint256 i = 0; i < owners.length; i++) {
            if (!multiSigValidatorStorage[msg.sender].isOwner[owners[i]]) {
                multiSigValidatorStorage[msg.sender].isOwner[owners[i]] = true;
                emit OwnerAdded(msg.sender, owners[i]);
            }
        }
        multiSigValidatorStorage[msg.sender].threshold = threshold;
        emit ThresholdChanged(msg.sender, threshold);
    }

    function validateUserOp(
        UserOperation calldata _userOp,
        bytes32 _userOpHash,
        uint256
    ) external view override returns (uint256 validationData) {
        if (!_signaturesAreValid(_userOpHash, _userOp.signature)) {
            return SIG_VALIDATION_FAILED;
        }
        return 0;
    }

    function validateSignature(
        bytes32 hash,
        bytes calldata signature
    ) public view override returns (uint256) {
        if (!_signaturesAreValid(hash, signature)) {
            return SIG_VALIDATION_FAILED;
        }
        return 0;
    }

    function _signaturesAreValid(
        bytes32 hash,
        bytes calldata signatures
    ) internal view returns (bool) {
        MultiSigValidatorStorage storage validatorStorage = multiSigValidatorStorage[msg.sender];
        uint256 threshold = validatorStorage.threshold;
        address lastOwner = address(0);
        address currentOwner;
        uint8 v;
        bytes32 r;
        bytes32 s;
        uint256 i;

        if (signatures.length < threshold * 65) {
            return false;
        }
        for (i = 0; i < threshold; i++) {
            (v, r, s) = signatureSplit(signatures, i);
            if (v > 30) {
                // If v > 30 then default v (27,28) has been adjusted for eth_sign flow
                // To support eth_sign and similar we adjust v and hash the messageHash with the Ethereum message prefix before applying ecrecover
                currentOwner = ecrecover(
                    ECDSA.toEthSignedMessageHash(hash),
                    v - 4,
                    r,
                    s
                );
            } else {
                // Default is the ecrecover flow with the provided data hash
                // Use ecrecover with the messageHash for EOA signatures
                currentOwner = ecrecover(hash, v, r, s);
            }
            // To prevent signer reuse
            // signatures are ordered by address
            if (currentOwner <= lastOwner || !validatorStorage.isOwner[currentOwner]) {
                return false;
            }
            lastOwner = currentOwner;
        }
        return true;
    }
}
