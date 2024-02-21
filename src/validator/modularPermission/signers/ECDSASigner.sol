pragma solidity ^0.8.0;

import {ECDSA} from "solady/utils/ECDSA.sol";
import {ISigner} from "../ISigner.sol";
import {ValidationData} from "../../../common/Types.sol";
import {SIG_VALIDATION_FAILED} from "../../../common/Constants.sol";

contract ECDSASigner is ISigner {
    using ECDSA for bytes32;

    mapping(address caller => mapping(bytes32 permissionId => mapping(address kernel => address))) public signer;

    function registerSigner(address kernel, bytes32 permissionId, bytes calldata data) external payable override {
        require(signer[msg.sender][permissionId][kernel] == address(0), "ECDSASigner: kernel already registered");
        require(data.length == 20, "ECDSASigner: invalid signer address");
        address signerAddress = address(bytes20(data[0:20]));
        signer[msg.sender][permissionId][kernel] = signerAddress;
    }

    function validateUserOp(address kernel, bytes32 permissionId, bytes32 userOpHash, bytes calldata signature)
        external
        payable
        override
        returns (ValidationData)
    {
        require(signer[msg.sender][permissionId][kernel] != address(0), "ECDSASigner: kernel not registered");
        address recovered = ECDSA.toEthSignedMessageHash(userOpHash).recover(signature);
        if (recovered == signer[msg.sender][permissionId][kernel]) {
            return ValidationData.wrap(0);
        }
        return SIG_VALIDATION_FAILED;
    }

    function validateSignature(address kernel, bytes32 permissionId, bytes32 messageHash, bytes calldata signature)
        external
        view
        override
        returns (ValidationData)
    {
        address signerAddress = signer[msg.sender][permissionId][kernel];
        require(signerAddress != address(0), "ECDSASigner: kernel not registered");
        if (messageHash.recover(signature) == signerAddress) {
            return ValidationData.wrap(0);
        }
        bytes32 ethHash = ECDSA.toEthSignedMessageHash(messageHash);
        address recovered = ethHash.recover(signature);
        if (recovered == signerAddress) {
            return ValidationData.wrap(0);
        }
        return SIG_VALIDATION_FAILED;
    }
}
