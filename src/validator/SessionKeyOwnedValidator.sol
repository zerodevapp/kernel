// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "solady/utils/ECDSA.sol";
import "solady/utils/EIP712.sol";
import "../utils/KernelHelper.sol";
import "../interfaces/IValidator.sol";
import "../common/Types.sol";

struct SessionKeyStorage {
    ValidUntil validUntil;
    ValidAfter validAfter;
}

contract SessionKeyOwnedValidator is IKernelValidator {
    event OwnerChanged(address indexed kernel, address indexed oldOwner, address indexed newOwner);

    mapping(address sessionKey => mapping(address kernel => SessionKeyStorage)) public sessionKeyStorage;

    function disable(bytes calldata _data) external payable override {
        address sessionKey = address(bytes20(_data[0:20]));
        delete sessionKeyStorage[sessionKey][msg.sender];
    }

    function enable(bytes calldata _data) external payable override {
        address sessionKey = address(bytes20(_data[0:20]));
        ValidAfter validAfter = ValidAfter.wrap(uint48(bytes6(_data[20:26])));
        ValidUntil validUntil = ValidUntil.wrap(uint48(bytes6(_data[26:32])));
        require(
            ValidUntil.unwrap(validUntil) > ValidAfter.unwrap(validAfter),
            "SessionKeyOwnedValidator: invalid validUntil/validAfter"
        ); // we do not allow validUntil == 0 here use validUntil == 2**48-1 instead
        sessionKeyStorage[sessionKey][msg.sender] = SessionKeyStorage(validUntil, validAfter);
    }

    function validateUserOp(UserOperation calldata _userOp, bytes32 _userOpHash, uint256)
        external
        payable
        override
        returns (ValidationData validationData)
    {
        address recovered = ECDSA.recover(_userOpHash, _userOp.signature);
        SessionKeyStorage storage sessionKey = sessionKeyStorage[recovered][msg.sender];
        if (ValidUntil.unwrap(sessionKey.validUntil) != 0) {
            return packValidationData(sessionKey.validAfter, sessionKey.validUntil);
        }

        bytes32 hash = ECDSA.toEthSignedMessageHash(_userOpHash);
        recovered = ECDSA.recover(hash, _userOp.signature);
        sessionKey = sessionKeyStorage[recovered][msg.sender];
        if (ValidUntil.unwrap(sessionKey.validUntil) == 0) {
            // we do not allow validUntil == 0 here
            return SIG_VALIDATION_FAILED;
        }
        validationData = packValidationData(sessionKey.validAfter, sessionKey.validUntil);
    }

    function validateSignature(bytes32 hash, bytes calldata signature) public view override returns (ValidationData) {
        address recovered = ECDSA.recover(hash, signature);
        SessionKeyStorage storage sessionKey = sessionKeyStorage[recovered][msg.sender];
        if (ValidUntil.unwrap(sessionKey.validUntil) != 0) {
            return packValidationData(sessionKey.validAfter, sessionKey.validUntil);
        }

        bytes32 ethhash = ECDSA.toEthSignedMessageHash(hash);
        recovered = ECDSA.recover(ethhash, signature);
        sessionKey = sessionKeyStorage[recovered][msg.sender];
        if (ValidUntil.unwrap(sessionKey.validUntil) == 0) {
            // we do not allow validUntil == 0 here
            return SIG_VALIDATION_FAILED;
        }
        return packValidationData(sessionKey.validAfter, sessionKey.validUntil);
    }

    function validCaller(address _caller, bytes calldata) external view override returns (bool) {
        SessionKeyStorage storage sessionKey = sessionKeyStorage[_caller][msg.sender];
        if (block.timestamp <= ValidAfter.unwrap(sessionKey.validAfter)) {
            return false;
        }
        if (block.timestamp > ValidUntil.unwrap(sessionKey.validUntil)) {
            return false;
        }
        return true;
    }
}
