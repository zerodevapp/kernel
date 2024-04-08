// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {LibClone} from "solady/utils/LibClone.sol";

contract KernelFactory {
    error InitializeError();

    address public immutable implementation;

    constructor(address _impl) {
        implementation = _impl;
    }

    function createAccount(bytes calldata data, bytes32 salt) public payable returns (address) {
        bytes32 actualSalt = keccak256(abi.encodePacked(data, salt));
        (bool alreadyDeployed, address account) =
            LibClone.createDeterministicERC1967(msg.value, implementation, actualSalt);
        if (!alreadyDeployed) {
            (bool success,) = account.call(data);
            if (!success) {
                revert InitializeError();
            }
        }
        return account;
    }

    function getAddress(bytes calldata data, bytes32 salt) public view virtual returns (address) {
        bytes32 actualSalt = keccak256(abi.encodePacked(data, salt));
        return LibClone.predictDeterministicAddressERC1967(implementation, actualSalt, address(this));
    }
}
