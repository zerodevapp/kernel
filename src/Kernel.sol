// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/draft-EIP712.sol";
import "../../plugin/IPlugin.sol";
import "../../../core/Helpers.sol";
import "../../../interfaces/IAccount.sol";
import "../../utils/OpinionatedExec.sol";
import "./Compatibility.sol";

struct WalletKernelStorage {
    address owner;
    uint256 nonce;
}

enum Operation {
    Call,
    DelegateCall
}

/// @title Kernel
/// @author taek<leekt216@gmail.com>
/// @notice wallet kernel for minimal wallet functionality
/// @dev supports only 1 owner and 1 threshold, multiple plugins
contract Kernel is IAccount, EIP712, Compatibility {
    error InvalidNonce();
    error InvalidSignatureLength();
    error QueryResult(bytes result);

    uint256 constant private SIG_VALIDATION_FAILED = 1;

    address public immutable entryPoint;

    constructor(address _entryPoint) EIP712("Kernel", "0.0.1") {
        entryPoint = _entryPoint;
        getKernelStorage().owner = address(1);
    }

    /// @notice get wallet kernel storage
    /// @dev used to get wallet kernel storage
    /// @return ws wallet kernel storage, consists of owner and nonces
    function getKernelStorage() internal pure returns (WalletKernelStorage storage ws) {
        bytes32 storagePosition = bytes32(uint256(keccak256("zero-dev.kernel")) - 1);
        assembly {
            ws.slot := storagePosition
        }
    }

    /// @notice initialize wallet kernel
    /// @dev this function should be called only once, implementation initialize is blocked by owner = address(1)
    /// @param _owner owner address
    function initialize(address _owner) external {
        WalletKernelStorage storage ws = getKernelStorage();
        require(ws.owner == address(0), "account: already initialized");
        ws.owner = _owner;
    }

    /// @notice Query plugin for data
    /// @dev this function will always fail, it should be used only to query plugin for data using error message
    /// @param _plugin Plugin address
    /// @param _data Data to query
    function queryPlugin(address _plugin, bytes calldata _data) external {
        (bool success, bytes memory _ret) = OpinionatedExec.delegateCall(_plugin, _data);
        if(success) {
            revert QueryResult(_ret);
        } else {
            assembly {
                revert(add(_ret, 32), mload(_ret))
            }
        }
    }

    /// @notice execute function call to external contract
    /// @dev this function will execute function call to external contract
    /// @param to target contract address
    /// @param value value to be sent
    /// @param data data to be sent
    /// @param operation operation type (call or delegatecall)
    function executeAndRevert(
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation
    ) external {
        require(msg.sender == entryPoint || msg.sender == getKernelStorage().owner, "account: not from entrypoint or owner");
        bool success;
        bytes memory ret;
        if(operation == Operation.DelegateCall) {
            (success, ret) = OpinionatedExec.delegateCall(to, data);
        } else {
            (success, ret) = OpinionatedExec.call(to, value, data);
        }
        if (!success) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
    }

    /// @notice validate user operation
    /// @dev this function will validate user operation and be called by EntryPoint
    /// @param userOp user operation
    /// @param userOpHash user operation hash
    /// @param missingAccountFunds funds needed to be reimbursed
    /// @return validationData validation data
    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
    external returns (uint256 validationData) {
        require(UserOperationLib.checkUserOpOffset(userOp), "userOp: invalid offset");
        require(msg.sender == entryPoint, "account: not from entryPoint");
        if(userOp.signature.length == 65){
            validationData = _validateUserOp(userOp, userOpHash);
        } else if(userOp.signature.length > 97) {
            // userOp.signature = address(plugin) + validUntil + validAfter + pluginData + pluginSignature
            address plugin = address(bytes20(userOp.signature[0:20]));
            uint48 validUntil = uint48(bytes6(userOp.signature[20:26]));
            uint48 validAfter = uint48(bytes6(userOp.signature[26:32]));
            bytes memory signature = userOp.signature[32:97];
            (bytes memory data, ) = abi.decode(userOp.signature[97:], (bytes, bytes));

            bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(
                keccak256("ValidateUserOpPlugin(address sender,uint48 validUntil,uint48 validAfter,address plugin,bytes data)"), // we are going to trust plugin for verification
                userOp.sender,
                validUntil,
                validAfter,
                plugin,
                keccak256(data)
            )));

            address signer = ECDSA.recover(digest, signature);
            if(getKernelStorage().owner != signer) {
                return SIG_VALIDATION_FAILED;
            }
            bytes memory ret = _delegateToPlugin(
                plugin,
                userOp,
                userOpHash,
                missingAccountFunds
            );
            bool res = abi.decode(ret, (bool));
            if(res) {
                return SIG_VALIDATION_FAILED;
            }
            validationData = _packValidationData(!res, validUntil, validAfter);
        } else {
            revert InvalidSignatureLength();
        }
        if(missingAccountFunds > 0) { // we are going to assume signature is valid at this point
            (bool success, ) = msg.sender.call{value: missingAccountFunds}("");
            (success);
            return validationData;
        }
    }

    function _validateUserOp(UserOperation calldata userOp, bytes32 userOpHash)
    internal returns (uint256 validationData) {
        bytes32 hash = ECDSA.toEthSignedMessageHash(userOpHash);
        address recovered = ECDSA.recover(hash,userOp.signature);
        WalletKernelStorage storage ws = getKernelStorage();
        if (ws.owner != recovered) {
            return SIG_VALIDATION_FAILED;
        }

        if (userOp.initCode.length == 0) {
            if(ws.nonce++ != userOp.nonce) {
                revert InvalidNonce();
            }
        }
    }

    /**
     * delegate the contract call to the plugin
     */
    function _delegateToPlugin(
        address plugin,
        UserOperation calldata userOp,
        bytes32 opHash,
        uint256 missingAccountFunds
    ) internal returns (bytes memory) {
        bytes memory data = abi.encodeWithSelector(IPlugin.validatePluginData.selector, 
            userOp,
            opHash,
            missingAccountFunds
        );
        (bool success, bytes memory ret) = OpinionatedExec.delegateCall(plugin, data); // Q: should we allow value > 0?
        if (!success) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
        return ret;
    }

    function isValidSignature(
        bytes32 _hash,
        bytes memory _signature
    ) public override view returns (bytes4) {
        bytes32 hash = ECDSA.toEthSignedMessageHash(_hash);
        address recovered = ECDSA.recover(hash, _signature);
        WalletKernelStorage storage ws = getKernelStorage();
        // Validate signatures
        if (ws.owner == recovered) {
            return 0x1626ba7e;
        } else {
            return 0xffffffff;
        }
    }
}
