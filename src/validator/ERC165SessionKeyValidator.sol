// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {UserOperation} from "I4337/interfaces/UserOperation.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {IKernelValidator} from "../interfaces/IKernelValidator.sol";
import {ValidAfter, ValidUntil, ValidationData, packValidationData} from "../common/Types.sol";
import {SIG_VALIDATION_FAILED} from "../common/Constants.sol";

// idea, we can make this merkle root
struct ERC165SessionKeyStorage {
    bool enabled;
    bytes4 selector;
    bytes4 interfaceId;
    ValidAfter validAfter;
    ValidUntil validUntil;
    uint32 addressOffset;
}

interface IERC165 {
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

contract ERC165SessionKeyValidator is IKernelValidator {
    mapping(address sessionKey => mapping(address kernel => ERC165SessionKeyStorage)) public sessionKeys;

    function enable(bytes calldata _data) external payable {
        address sessionKey = address(bytes20(_data[0:20]));
        bytes4 interfaceId = bytes4(_data[20:24]);
        bytes4 selector = bytes4(_data[24:28]);
        ValidAfter validAfter = ValidAfter.wrap(uint48(bytes6(_data[28:34])));
        ValidUntil validUntil = ValidUntil.wrap(uint48(bytes6(_data[34:40])));
        uint32 addressOffset = uint32(bytes4(_data[40:44]));
        sessionKeys[sessionKey][msg.sender] =
            ERC165SessionKeyStorage(true, selector, interfaceId, validAfter, validUntil, addressOffset);
    }

    function disable(bytes calldata _data) external payable {
        address sessionKey = address(bytes20(_data[0:20]));

        delete sessionKeys[sessionKey][msg.sender];
    }

    function validateSignature(bytes32, bytes calldata) external pure override returns (ValidationData) {
        revert NotImplemented();
    }

    function validateUserOp(UserOperation calldata _userOp, bytes32 _userOpHash, uint256)
        external
        payable
        returns (ValidationData)
    {
        bytes32 hash = ECDSA.toEthSignedMessageHash(_userOpHash);
        address recovered = ECDSA.recover(hash, _userOp.signature);
        ERC165SessionKeyStorage storage sessionKey = sessionKeys[recovered][_userOp.sender];
        if (!sessionKey.enabled) {
            return SIG_VALIDATION_FAILED;
        }
        require(bytes4(_userOp.callData[0:4]) == sessionKey.selector, "not supported selector");
        address token = address(bytes20(_userOp.callData[sessionKey.addressOffset:sessionKey.addressOffset + 20]));
        require(IERC165(token).supportsInterface(sessionKey.interfaceId), "does not support interface");
        return packValidationData(sessionKey.validAfter, sessionKey.validUntil);
    }

    function validCaller(address, bytes calldata) external pure override returns (bool) {
        revert NotImplemented();
    }
}
