// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import "./plugin/IPlugin.sol";
import "account-abstraction/core/Helpers.sol";
import "account-abstraction/interfaces/IAccount.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";
import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
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
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
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
    function execute(address to, uint256 value, bytes calldata data, Operation operation) external {
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
        // validateUserOp has to be able to handle
        // 1) 2fa
        // 2) session key
        // signature
        //  4 bytes
        // <--------> | <-----------> | <---------->
        //   mode(0)     data_plugin     sig_plugin => plugin mode, use delegatecall
        // <--------> | <---------------> | <-----------> | <----------> | <------------> 
        //   mode(1)     addr_plugin_hot     data_plugin     sig_plugin     sig_verifier => plugin override mode, use call(to be safe)
        //
        //  interface IPlugin {
        //      function pluginValidation(
        //        userOp,
        //        opHash,
        //        pluginDataAndSig
        //      ) external returns(uint256 validationData, bytes calldata data);
        //  }
        //
        require(msg.sender == address(entryPoint), "account: not from entryPoint");
        bytes4 sig = bytes4(userOp.callData[0:4]);
        address plugin = getKernelStorage().plugins[sig];
        if(plugin == address(0)) {
            plugin = getKernelStorage().defaultPlugin;
        }
        // mode based signature
        bytes4 mode = bytes4(userOp.signature[0:4]); // mode == 00..00 use plugins
        // validation phase
        if(mode == 0x00000001) {
            plugin = address(bytes20(userOp.signature[4: 24]));
            _hotPluginValidation(plugin, userOp, userOpHash, userOp.signature[24:]);
        } else if ( plugin == address(0)) {
            validationData = _validateUserOp(userOp.signature[4:], userOpHash);
        } else {
            (validationData,) = _delegateToPlugin(plugin, userOp, userOpHash, userOp.signature[4:]);
        }

        if (missingAccountFunds > 0) {
            // we are going to assume signature is valid at this point
            (bool success,) = msg.sender.call{value: missingAccountFunds}("");
            (success);
            return validationData;
        }
    }

    function _validateUserOp(bytes calldata signature, bytes32 userOpHash)
        internal
        view
        returns (uint256 validationData)
    {
        WalletKernelStorage storage ws = getKernelStorage();
        if (ws.owner == ECDSA.recover(userOpHash, signature)) {
            return validationData;
        }

        bytes32 hash = ECDSA.toEthSignedMessageHash(userOpHash);
        address recovered = ECDSA.recover(hash, signature);
        if (ws.owner != recovered) {
            return SIG_VALIDATION_FAILED;
        }
    }

    function _delegateToPlugin(address plugin, UserOperation calldata userOp, bytes32 opHash, bytes calldata pluginDataAndSig)
        internal
        returns (uint256, bytes32)
    {
        bytes memory data = abi.encodeWithSelector(IPlugin.validatePluginData.selector, userOp, opHash, pluginDataAndSig);
        (bool success, bytes memory ret) = Exec.delegateCall(plugin, data); // Q: should we allow value > 0?
        if (!success || ret.length != 32) {
            // return 0 (SIG_VALIDATION_FAILED)
            return (0, bytes32(0));
        }
        return abi.decode(ret, (uint256, bytes32));
    }

    function _hotPluginValidation(address plugin, UserOperation calldata userOp, bytes32 opHash, bytes calldata pluginDataAndSig)
        internal
        returns (uint256, bytes32)
    {
        bytes memory data = abi.encodeWithSelector(IPlugin.validatePluginData.selector, userOp, opHash, pluginDataAndSig);
        (bool success, bytes memory ret) = Exec.call(plugin,0, data);
        if (!success || ret.length != 32) {
            // return 0 (SIG_VALIDATION_FAILED)
            return (0, bytes32(0));
        }
        return abi.decode(ret, (uint256, bytes32));
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
