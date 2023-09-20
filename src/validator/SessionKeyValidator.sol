pragma solidity ^0.8.0;

import "solady/utils/ECDSA.sol";
import "../interfaces/IValidator.sol";
import "solady/utils/MerkleProofLib.sol";
import "../common/Constants.sol";
import "../common/Enum.sol";
import "../common/Structs.sol";
import "../common/Types.sol";

contract ExecuteSessionKeyValidator is IKernelValidator {
    mapping(address sessionKey => mapping(address kernel => SessionData)) public sessionData;

    function enable(bytes calldata _data) external payable {
        address sessionKey = address(bytes20(_data[0:20]));
        bytes32 merkleRoot = bytes32(_data[20:52]);
        ValidAfter validAfter = ValidAfter.wrap(uint48(bytes6(_data[52:58])));
        ValidUntil validUntil = ValidUntil.wrap(uint48(bytes6(_data[58:64])));
        address paymaster = address(bytes20(_data[64:84]));
        sessionData[sessionKey][msg.sender] = SessionData(merkleRoot, validAfter, validUntil, paymaster, true);
    }

    function disable(bytes calldata _data) external payable {
        address sessionKey = address(bytes20(_data[0:20]));
        address kernel = msg.sender;
        sessionData[sessionKey][kernel].enabled = false;
    }

    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256)
        external
        payable
        returns (ValidationData)
    {
        // userOp.signature = signer + signature + permission + merkleProof
        address sessionKey = address(bytes20(userOp.signature[0:20]));
        bytes calldata signature = userOp.signature[20:85];
        SessionData storage session = sessionData[sessionKey][msg.sender];
        require(session.enabled, "SessionKeyValidator: session key not enabled");
        if (session.merkleRoot == bytes32(0)) {
            // sessionKey allowed to execute any tx
            return packValidationData(session.validAfter, session.validUntil);
        }
        if (session.paymaster == address(1)) {
            require(userOp.paymasterAndData.length != 0, "SessionKeyValidator: paymaster not set");
        } else if (session.paymaster != address(0)) {
            require(
                address(bytes20(userOp.paymasterAndData[0:20])) == session.paymaster,
                "SessionKeyValidator: paymaster mismatch"
            );
        }

        (Permission memory permission, bytes32[] memory merkleProof) =
            abi.decode(userOp.signature[85:], (Permission, bytes32[]));
        require(
            permission.target == address(0) || address(bytes20(userOp.callData[16:36])) == permission.target,
            "SessionKeyValidator: target mismatch"
        );
        require(
            uint256(bytes32(userOp.callData[36:68])) <= permission.valueLimit,
            "SessionKeyValidator: value limit exceeded"
        );
        require(
            Operation(uint8(uint256(bytes32(userOp.callData[100:132])))) == permission.operation,
            "SessionKeyValidator: operation mismatch"
        );
        uint256 dataOffset = uint256(bytes32(userOp.callData[68:100])) + 4; // adding 4 for msg.sig
        uint256 dataLength = uint256(bytes32(userOp.callData[dataOffset:dataOffset + 32]));
        bytes calldata data = userOp.callData[dataOffset + 32:dataOffset + 32 + dataLength];
        require(bytes4(data[0:4]) == permission.sig, "SessionKeyValidator: sig mismatch");
        for (uint256 i = 0; i < permission.rules.length; i++) {
            ParamRule memory rule = permission.rules[i];
            bytes32 param = bytes32(data[4 + rule.offset:4 + rule.offset + 32]);
            if (rule.condition == ParamCondition.EQUAL) {
                require(param == rule.param, "SessionKeyValidator: param mismatch");
            } else if (rule.condition == ParamCondition.GREATER_THAN) {
                require(param > rule.param, "SessionKeyValidator: param mismatch");
            } else if (rule.condition == ParamCondition.LESS_THAN) {
                require(param < rule.param, "SessionKeyValidator: param mismatch");
            } else if (rule.condition == ParamCondition.GREATER_THAN_OR_EQUAL) {
                require(param >= rule.param, "SessionKeyValidator: param mismatch");
            } else if (rule.condition == ParamCondition.LESS_THAN_OR_EQUAL) {
                require(param <= rule.param, "SessionKeyValidator: param mismatch");
            } else if (rule.condition == ParamCondition.NOT_EQUAL) {
                require(param != rule.param, "SessionKeyValidator: param mismatch");
            }
        }
        bool result = MerkleProofLib.verify(merkleProof, session.merkleRoot, keccak256(abi.encode(permission)))
            && (sessionKey == ECDSA.recover(ECDSA.toEthSignedMessageHash(userOpHash), signature));
        if (!result) {
            return SIG_VALIDATION_FAILED;
        }
        return packValidationData(session.validAfter, session.validUntil);
    }

    function validCaller(address, bytes calldata) external pure returns (bool) {
        revert("SessionKeyValidator: not implemented");
    }

    function validateSignature(bytes32, bytes calldata) external pure returns (ValidationData) {
        revert("SessionKeyValidator: not implemented");
    }
}
