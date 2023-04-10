//SPDX-License-Identifier: GPL
pragma solidity ^0.8.7;

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */
/* solhint-disable reason-string */

import "./ZeroDevBasePlugin.sol";
import "openzeppelin-contracts/contracts/utils/cryptography/MerkleProof.sol";
using ECDSA for bytes32;
/**
 * Main EIP4337 module.
 * Called (through the fallback module) using "delegate" from the GnosisSafe as an "IAccount",
 * so must implement validateUserOp
 * holds an immutable reference to the EntryPoint
 */

struct ZeroDevSessionKeyStorageStruct {
    mapping(address => bool) revoked;
}

contract ZeroDevSessionKeyPlugin is ZeroDevBasePlugin {
    // return value in case of signature failure, with no time-range.
    // equivalent to packSigTimeRange(true,0,0);
    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    event SessionKeyRevoked(address indexed key);

    constructor() EIP712("ZeroDevSessionKeyPlugin", "0.0.1") {}

    function getPolicyStorage() internal pure returns (ZeroDevSessionKeyStorageStruct storage s) {
        bytes32 position = bytes32(uint256(keccak256("zero-dev.account.eip4337.sessionkey")) - 1);
        assembly {
            s.slot := position
        }
    }

    // revoke session key
    function revokeSessionKey(address _key) external {
        getPolicyStorage().revoked[_key] = true;
        emit SessionKeyRevoked(_key);
    }

    function revoked(address _key) external view returns (bool) {
        return getPolicyStorage().revoked[_key];
    }

    function _validatePluginData(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        bytes calldata data,
        bytes calldata signature
    ) internal view override returns (bool) {
        address sessionKey = address(bytes20(data[0:20]));
        require(!getPolicyStorage().revoked[sessionKey], "session key revoked");
        bytes32 merkleRoot = bytes32(data[20:52]);
        if(merkleRoot == bytes32(0)) {
            // means this session key has sudo permission
            signature = signature[33:98];
        } else {
            uint8 leafLength = uint8(signature[0]);
            bytes32[] memory proof;
            bytes32 leaf;
            if(leafLength == 20) {
                leaf = keccak256(signature[1:21]);
                proof = abi.decode(signature[86:], (bytes32[]));
                require(keccak256(userOp.callData[16:36]) == keccak256(signature[1:21]), "invalid session key");
                signature = signature[21:86];
            } else if(leafLength == 24) {
                leaf = keccak256(signature[1:25]);
                proof = abi.decode(signature[90:], (bytes32[]));
                require(keccak256(userOp.callData[16:36]) == keccak256(signature[1:21]), "invalid session key");
                uint256 offset = uint256(bytes32(userOp.callData[68:100]));
                bytes calldata sig = userOp.callData[offset + 36: offset + 40];
                require(keccak256(sig) == keccak256(signature[21:25]));
                signature = signature[25:90];
            }
            require(MerkleProof.verify(proof, merkleRoot, leaf), "invalide merkle root");
        }
        bytes32 digest = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    keccak256("Session(bytes32 userOpHash,uint256 nonce)"), // we are going to trust plugin for verification
                    userOpHash,
                    userOp.nonce
                )
            )
        );
        address recovered = digest.recover(signature);
        require(recovered == sessionKey, "account: invalid signature");
        return true;
    }
}
