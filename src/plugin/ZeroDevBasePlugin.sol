// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import "account-abstraction/interfaces/IAccount.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";
import "./IPlugin.sol";
abstract contract ZeroDevBasePlugin is IPlugin, EIP712 {
    function validatePluginData(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        override
        returns (bool validated)
    {
        // data offset starts at 97
        (bytes calldata data, bytes calldata signature) = parseDataAndSignature(userOp.signature[97:]);
        validated = _validatePluginData(userOp, userOpHash, data, signature);
    }

    function _validatePluginData(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        bytes calldata data,
        bytes calldata signature
    ) internal virtual returns (bool success);

    function parseDataAndSignature(bytes calldata _packed)
        public
        pure
        returns (bytes calldata data, bytes calldata signature)
    {
        uint256 dataPosition = uint256(bytes32(_packed[0:32]));
        uint256 dataLength = uint256(bytes32(_packed[dataPosition:dataPosition + 32]));
        uint256 signaturePosition = uint256(bytes32(_packed[32:64]));
        uint256 signatureLength = uint256(bytes32(_packed[signaturePosition:signaturePosition + 32]));
        data = _packed[dataPosition + 32:dataPosition + 32 + dataLength];
        signature = _packed[signaturePosition + 32:signaturePosition + 32 + signatureLength];

        require(dataPosition + 64 + ((dataLength) / 32) * 32 == signaturePosition, "invalid data");
        require(signaturePosition + 64 + ((signatureLength) / 32) * 32 == _packed.length, "invalid signature");
    }
}
