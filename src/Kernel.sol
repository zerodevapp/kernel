// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import "./plugin/IPlugin.sol";
import "account-abstraction/core/Helpers.sol";
import "account-abstraction/interfaces/IAccount.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";
import {EntryPoint} from  "account-abstraction/core/EntryPoint.sol";
import "./utils/Exec.sol";
import "./abstract/Compatibility.sol";
import "./abstract/KernelStorage.sol";

/// @title Kernel
/// @author taek<leekt216@gmail.com>
/// @notice wallet kernel for minimal wallet functionality
/// @dev supports only 1 owner, multiple plugins
contract Kernel is IAccount, EIP712, Compatibility, KernelStorage {
    error InvalidNonce();
    error InvalidSignatureLength();
    error QueryResult(bytes result);

    string public constant name = "Kernel";

    string public constant version = "0.0.1";

    constructor(IEntryPoint _entryPoint) EIP712(name, version) KernelStorage(_entryPoint) {}

    fallback() external payable {
        // should we do entrypoint check here?
        bytes4 sig = msg.sig;
        address facet = getKernelStorage().facets[sig];
        assembly {
            calldatacopy(0,0,calldatasize())
            let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 {
                revert(0, returndatasize())
            }
            default {
                return(0, returndatasize())
            }
        }
    }

    /// @notice Query plugin for data
    /// @dev this function will always fail, it should be used only to query plugin for data using error message
    /// @param _plugin Plugin address
    /// @param _data Data to query
    function queryPlugin(address _plugin, bytes calldata _data) external {
        (bool success, bytes memory _ret) = Exec.delegateCall(_plugin, _data);
        if (success) {
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
    function executeAndRevert(address to, uint256 value, bytes calldata data, Operation operation) external {
        require(
            msg.sender == address(entryPoint) || msg.sender == getKernelStorage().owner,
            "account: not from entrypoint or owner"
        );
        bool success;
        bytes memory ret;
        if (operation == Operation.DelegateCall) {
            (success, ret) = Exec.delegateCall(to, data);
        } else {
            (success, ret) = Exec.call(to, value, data);
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
        external
        returns (uint256 validationData)
    {
        require(msg.sender == address(entryPoint), "account: not from entryPoint");
        address plugin = getKernelStorage().plugins[bytes4(userOp.callData[0:4])];
        if( plugin == address(0) && getKernelStorage().defaultPlugin != address(0)) {
            plugin = getKernelStorage().defaultPlugin;
        }
        if (plugin == address(0)) {
            validationData = _validateUserOp(userOp, userOpHash);
        } else {
            validationData = _delegateToPlugin(plugin, userOp, userOpHash, missingAccountFunds);
        }
        if (missingAccountFunds > 0) {
            // we are going to assume signature is valid at this point
            (bool success,) = msg.sender.call{value: missingAccountFunds}("");
            (success);
            return validationData;
        }
    }

    function _validateUserOp(UserOperation calldata userOp, bytes32 userOpHash)
        internal
        view
        returns (uint256 validationData)
    {
        WalletKernelStorage storage ws = getKernelStorage();
        if (ws.owner == ECDSA.recover(userOpHash, userOp.signature)) {
            return validationData;
        }

        bytes32 hash = ECDSA.toEthSignedMessageHash(userOpHash);
        address recovered = ECDSA.recover(hash, userOp.signature);
        if (ws.owner != recovered) {
            return SIG_VALIDATION_FAILED;
        }
    }

    function _delegateToPlugin(address _plugin, UserOperation calldata _userOp, bytes32 _userOpHash, uint256 _missingFunds) internal returns(uint256 ret){
        //
    }

    /// @notice validate signature using eip1271
    /// @dev this function will validate signature using eip1271
    /// @param _hash hash to be signed
    /// @param _signature signature
    function isValidSignature(bytes32 _hash, bytes memory _signature) public view override returns (bytes4) {
        WalletKernelStorage storage ws = getKernelStorage();
        if (ws.owner == ECDSA.recover(_hash, _signature)) {
            return 0x1626ba7e;
        }
        bytes32 hash = ECDSA.toEthSignedMessageHash(_hash);
        address recovered = ECDSA.recover(hash, _signature);
        // Validate signatures
        if (ws.owner == recovered) {
            return 0x1626ba7e;
        } else {
            return 0xffffffff;
        }
    }
}