// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "./IValidator.sol";
import "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import "src/utils/KernelHelper.sol";
import "src/interfaces/IAddressBook.sol";

contract MultiECDSAValidator is IKernelValidator {
    event OwnerAdded(address indexed kernel, address indexed owner);
    event OwnerRemoved(address indexed kernel, address indexed owner);

    mapping(address owner => mapping(address kernel => bool) hello) public isOwner;

    function disable(bytes calldata _data) external override {
        address[] memory owners = abi.decode(_data, (address[]));
        for (uint256 i = 0; i < owners.length; i++) {
            isOwner[owners[i]][msg.sender] = false;
            emit OwnerRemoved(msg.sender, owners[i]);
        }
    }

    function enable(bytes calldata _data) external override {
        address addressBook = address(bytes20(_data));
        address[] memory owners = IAddressBook(addressBook).getOwners();
        for (uint256 i = 0; i < owners.length; i++) {
            isOwner[owners[i]][msg.sender] = true;
            emit OwnerAdded(msg.sender, owners[i]);
        }
    }

    function validateUserOp(UserOperation calldata _userOp, bytes32 _userOpHash, uint256)
        external
        view
        override
        returns (uint256 validationData)
    {
        address signer = ECDSA.recover(_userOpHash, _userOp.signature);
        if (isOwner[signer][msg.sender]) {
            return 0;
        }

        bytes32 hash = ECDSA.toEthSignedMessageHash(_userOpHash);
        signer = ECDSA.recover(hash, _userOp.signature);
        if (!isOwner[signer][msg.sender]) {
            return SIG_VALIDATION_FAILED;
        }
        return 0;
    }

    function validateSignature(bytes32 hash, bytes calldata signature) public view override returns (uint256) {
        address signer = ECDSA.recover(hash, signature);
        if(isOwner[signer][msg.sender]) {
            return 0;
        }
        bytes32 ethHash = ECDSA.toEthSignedMessageHash(hash);
        signer = ECDSA.recover(ethHash, signature);
        if (!isOwner[signer][msg.sender]) {
            return SIG_VALIDATION_FAILED;
        }
        return 0;
    }
}
