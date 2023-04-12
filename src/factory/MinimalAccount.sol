// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import "account-abstraction/interfaces/UserOperation.sol";
import "account-abstraction/interfaces/IAccount.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";
import "src/utils/Exec.sol";
import "src/abstract/KernelStorage.sol";
import "src/abstract/Compatibility.sol";

contract MinimalAccount is IAccount, KernelStorage, Compatibility {
    error InvalidNonce();

    constructor(IEntryPoint _entryPoint) KernelStorage(_entryPoint) {}

    function initialize(address _owner) external {
        require(getKernelStorage().owner == address(0), "Already initialized");
        getKernelStorage().owner = _owner;
    }

    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingFunds)
        external
        returns (uint256)
    {
        require(msg.sender == address(entryPoint), "account: not from entrypoint");
        bytes32 hash = ECDSA.toEthSignedMessageHash(userOpHash);
        address recovered = ECDSA.recover(hash, userOp.signature);
        WalletKernelStorage storage ws = getKernelStorage();
        if (ws.owner != recovered) {
            return SIG_VALIDATION_FAILED;
        }

        if (missingFunds > 0) {
            (bool success,) = msg.sender.call{value: missingFunds}("");
            (success);
        }
        return 0;
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
