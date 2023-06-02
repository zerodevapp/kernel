// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "account-abstraction/core/EntryPoint.sol";
import "forge-std/Test.sol";
import "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

library ERC4337Utils {
    function fillUserOp(EntryPoint _entryPoint, address _sender, bytes memory _data)
        internal
        view
        returns (UserOperation memory op)
    {
        op.sender = _sender;
        op.nonce = _entryPoint.getNonce(_sender, 0);
        op.callData = _data;
        op.callGasLimit = 10000000;
        op.verificationGasLimit = 10000000;
        op.preVerificationGas = 50000;
        op.maxFeePerGas = 50000;
        op.maxPriorityFeePerGas = 1;
    }

    function signUserOpHash(EntryPoint _entryPoint, Vm _vm, uint256 _key, UserOperation memory _op)
        internal
        view
        returns (bytes memory signature)
    {
        bytes32 hash = _entryPoint.getUserOpHash(_op);
        (uint8 v, bytes32 r, bytes32 s) = _vm.sign(_key, ECDSA.toEthSignedMessageHash(hash));
        signature = abi.encodePacked(r, s, v);
    }
}
