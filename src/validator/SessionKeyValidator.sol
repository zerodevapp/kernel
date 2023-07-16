pragma solidity ^0.8.0;

import "src/interfaces/IValidator.sol";
import "account-abstraction/core/Helpers.sol";
import "openzeppelin-contracts/contracts/utils/cryptography/MerkleProof.sol";
import "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";

contract ExecuteSessionKeyValidator is IKernelValidator {
    enum ParamCondition {
        EQUAL,
        GREATER_THAN,
        LESS_THAN,
        GREATER_THAN_OR_EQUAL,
        LESS_THAN_OR_EQUAL,
        NOT_EQUAL
    }

    struct ParamRule {
        uint8 index;
        ParamCondition condition;
        bytes32 param;
    }

    struct Permission {
        uint256 valueLimit;
        address target;
        bytes4 sig;
        ParamRule[] rules;
    }

    // TODO : gas spending limit
    struct SessionData {
        bool enabled;
        uint48 validUntil;
        uint48 validAfter;
        bytes32 merkleRoot;
    }

    mapping(address sessionKey => mapping(address kernel => SessionData)) public sessionData;

    function enable(bytes calldata _data) external {
        address sessionKey = address(bytes20(_data[0:20]));
        bytes32 merkleRoot = bytes32(_data[20:52]);
        uint48 validUntil = uint48(bytes6(_data[52:58]));
        uint48 validAfter = uint48(bytes6(_data[58:64]));

        sessionData[sessionKey][msg.sender] = SessionData(true, validUntil, validAfter, merkleRoot);
    }

    function disable(bytes calldata _data) external {
        address sessionKey = address(bytes20(_data[0:20]));
        address kernel = msg.sender;
        delete sessionData[sessionKey][kernel];
    }

    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingFunds)
        external
        returns (uint256)
    {
        // userOp.signature = signature + permission + merkleProof
        bytes calldata signature = userOp.signature[0:65];
        address sessionKey = ECDSA.recover(userOpHash, signature);
        SessionData storage session = sessionData[sessionKey][msg.sender];
        require(session.enabled, "SessionKeyValidator: session key not enabled");
        if (session.merkleRoot == bytes32(0)) {
            // sessionKey allowed to execute any tx
            return _packValidationData(false, session.validUntil, session.validAfter);
        }

        (Permission memory permission, bytes32[] memory merkleProof) =
            abi.decode(userOp.signature[65:], (Permission, bytes32[]));
        address target = address(bytes20(userOp.callData[16:36]));
        require(target == permission.target, "SessionKeyValidator: target mismatch");
        uint256 value = uint256(bytes32(userOp.callData[36:68]));
        require(value <= permission.valueLimit, "SessionKeyValidator: value limit exceeded");
        {
            uint256 dataOffset = uint256(bytes32(userOp.callData[68:100]));
            uint256 dataLength = uint256(bytes32(userOp.callData[dataOffset:dataOffset + 32]));
            bytes calldata data = userOp.callData[dataOffset + 32:dataOffset + 32 + dataLength];
            bytes4 sig = bytes4(data[0:4]);
            require(sig == permission.sig, "SessionKeyValidator: sig mismatch");
            for (uint256 i = 0; i < permission.rules.length; i++) {
                ParamRule memory rule = permission.rules[i];
                bytes32 param = bytes32(data[4 + rule.index * 32:4 + rule.index * 32 + 32]);
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
            bytes32 leaf = keccak256(abi.encodePacked(target, value, data));
            MerkleProof.verify(merkleProof, session.merkleRoot, leaf);
        }
    }

    function validCaller(address caller, bytes calldata _data) external view returns (bool) {
        revert("SessionKeyValidator: not implemented");
    }

    function validateSignature(bytes32 hash, bytes calldata _data) external view returns (uint256) {
        revert("SessionKeyValidator: not implemented");
    }
}
