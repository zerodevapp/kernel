//SPDX-License-Identifier: GPL
pragma solidity ^0.8.7;

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */
/* solhint-disable reason-string */

import "./ZeroDevBasePlugin.sol";
import "./policy/IPolicy.sol";

using ECDSA for bytes32;
/**
 * Main EIP4337 module.
 * Called (through the fallback module) using "delegate" from the GnosisSafe as an "IAccount",
 * so must implement validateUserOp
 * holds an immutable reference to the EntryPoint
 * Inherits GnosisSafeStorage so that it can reference the memory storage
 */
struct ZeroDevSessionKeyStorageStruct {
    mapping(address => bool) revoked;
    mapping(address => uint256) sessionNonce;
}

contract ZeroDevSessionKeyPlugin is ZeroDevBasePlugin {

    // return value in case of signature failure, with no time-range.
    // equivalent to packSigTimeRange(true,0,0);
    uint256 constant internal SIG_VALIDATION_FAILED = 1;

    event SessionKeyRevoked(address indexed key);

    constructor() EIP712("ZeroDevSessionKeyPlugin", "1.0.0") {
    }

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

    function sessionNonce(address _key) external view returns (uint256) {
        return getPolicyStorage().sessionNonce[_key];
    }

    /**
     * delegate-called (using execFromModule) through the fallback, so "real" msg.sender is attached as last 20 bytes
     */
    function _validatePluginData(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        bytes calldata data,
        bytes calldata signature
    ) internal override returns (bool) {
        address sessionKey = address(bytes20(data[0:20]));
        if(getPolicyStorage().revoked[sessionKey]) {
            return false;
        }

        address policy = address(bytes20(data[20:40]));
        if(!_checkPolicy(policy, userOp.callData)) {
            return false;
        }

        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(
            keccak256("Session(bytes32 userOpHash,uint256 nonce)"), // we are going to trust plugin for verification
            userOpHash,
            getPolicyStorage().sessionNonce[sessionKey]++
        )));
        address recovered = digest.recover(signature);
        require(recovered == sessionKey, "account: invalid signature");
        return true;
    }

    function _checkPolicy(address _policy, bytes calldata _calldata) internal view returns (bool) {
        (bool success, bytes memory returndata) = _policy.staticcall(_calldata);
        if (!success) {
            assembly {
                revert(add(32, returndata), mload(returndata))
            }
        }
        return abi.decode(returndata, (bool));
    }
}
