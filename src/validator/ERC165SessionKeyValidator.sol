// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./IValidator.sol";
import "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import "openzeppelin-contracts/contracts/utils/introspection/IERC165.sol";
import "src/utils/KernelHelper.sol";

// idea, we can make this merkle root
struct ERC165SessionKeyStorage {
    bool enabled;
    bytes4 selector;
    bytes4 interfaceId;
    uint48 validUntil;
    uint48 validAfter;
    uint32 addressOffset;
}

contract ERC165SessionKeyValidator is IKernelValidator {
    mapping(address sessionKey => mapping(address kernel => ERC165SessionKeyStorage)) public sessionKeys;

    function enable(bytes calldata _data) external {
        address sessionKey = address(bytes20(_data[0:20]));
        bytes4 interfaceId = bytes4(_data[20:24]);
        bytes4 selector = bytes4(_data[24:28]);
        uint48 validUntil = uint48(bytes6(_data[28:34]));
        uint48 validAfter = uint48(bytes6(_data[34:40]));
        uint32 addressOffset = uint32(bytes4(_data[40:44]));
        sessionKeys[sessionKey][msg.sender] =
            ERC165SessionKeyStorage(true, selector, interfaceId, validUntil, validAfter, addressOffset);
    }

    function disable(bytes calldata _data) external {
        address sessionKey = address(bytes20(_data[0:20]));

        delete sessionKeys[sessionKey][msg.sender];
    }

    function validateSignature(bytes32, bytes calldata) external pure override returns (uint256) {
        revert("not implemented");
    }

    function validateUserOp(UserOperation calldata _userOp, bytes32 _userOpHash, uint256)
        external
        view
        returns (uint256)
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
        return (uint256(sessionKey.validAfter) << 160) | (uint256(sessionKey.validUntil) << (48 + 160));
    }
}
