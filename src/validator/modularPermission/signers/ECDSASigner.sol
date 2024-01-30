pragma solidity ^0.8.0;

import {ECDSA} from "solady/utils/ECDSA.sol";
import {ISigner} from "../ISigner.sol";
import {ValidationData} from "../../../common/Types.sol";

contract ECDSASigner is ISigner{
    using ECDSA for bytes32;

    mapping(bytes32 permissionId => mapping(address kernel =>  address)) public signer;

    function registerSigner(address kernel, bytes32 permissionId, bytes calldata data) external payable override {
        require(signer[permissionId][kernel] == address(0), "ECDSASigner: kernel already registered");
        require(data.length == 20, "ECDSASigner: invalid signer address");
        address signerAddress = address(bytes20(data[0:20]));
        signer[permissionId][kernel] = signerAddress;
    }

    function validateUserOp(
        address kernel,
        bytes32 permissionId,
        bytes32 userOpHash,
        bytes calldata signature
    ) external payable override returns (ValidationData) {
        require(signer[permissionId][kernel] != address(0), "ECDSASigner: kernel not registered");
        address recovered = userOpHash.recover(signature);
        require(recovered == signer[permissionId][kernel], "ECDSASigner: invalid signature");
        return ValidationData.wrap(0);
    }

    function validateSignature(
        address kernel,
        bytes32 permissionId,
        bytes32 messageHash,
        bytes calldata signature
    ) external view override returns (ValidationData) {
        require(signer[permissionId][kernel] != address(0), "ECDSASigner: kernel not registered");
        address recovered = messageHash.recover(signature);
        require(recovered == signer[permissionId][kernel], "ECDSASigner: invalid signature");
        return ValidationData.wrap(0);
    }
}
