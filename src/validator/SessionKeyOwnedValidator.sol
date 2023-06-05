// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "./IValidator.sol";
import "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import "src/utils/KernelHelper.sol";
import "account-abstraction/core/Helpers.sol";

struct SessionKeyStorage {
    uint48 validUntil;
    uint48 validAfter;
}

contract SessionKeyOwnedValidator is IKernelValidator {
    event OwnerChanged(address indexed kernel, address indexed oldOwner, address indexed newOwner);

    mapping(address sessionKey => mapping(address kernel => SessionKeyStorage)) public sessionKeyStorage;

    function disable(bytes calldata _data) external override {
        address sessionKey = address(bytes20(_data[0:20]));
        delete sessionKeyStorage[sessionKey][msg.sender];
    }

    function enable(bytes calldata _data) external override {
        address sessionKey = address(bytes20(_data[0:20]));
        uint48 validUntil = uint48(bytes6(_data[20:26]));
        uint48 validAfter = uint48(bytes6(_data[26:32]));
        require(validUntil > validAfter, "SessionKeyOwnedValidator: invalid validUntil/validAfter"); // we do not allow validUntil == 0 here use validUntil == 2**48-1 instead
        sessionKeyStorage[sessionKey][msg.sender] = SessionKeyStorage(validUntil, validAfter);
    }

    function validateUserOp(UserOperation calldata _userOp, bytes32 _userOpHash, uint256)
        external
        view
        override
        returns (uint256 validationData)
    {
        bytes32 hash = ECDSA.toEthSignedMessageHash(_userOpHash);
        address recovered = ECDSA.recover(hash, _userOp.signature);

        SessionKeyStorage storage sessionKey = sessionKeyStorage[recovered][msg.sender];
        if (sessionKey.validUntil == 0 ) { // we do not allow validUntil == 0 here
            return SIG_VALIDATION_FAILED;
        }
        return _packValidationData(false, sessionKey.validUntil, sessionKey.validAfter);
    }

    function validateSignature(bytes32 hash, bytes calldata signature) public view override returns (uint256) {
        bytes32 ethhash = ECDSA.toEthSignedMessageHash(hash);
        address recovered = ECDSA.recover(ethhash, signature);

        SessionKeyStorage storage sessionKey = sessionKeyStorage[recovered][msg.sender];
        if (sessionKey.validUntil == 0 ) { // we do not allow validUntil == 0 here
            return SIG_VALIDATION_FAILED;
        }
        return _packValidationData(false, sessionKey.validUntil, sessionKey.validAfter);
    }
}
