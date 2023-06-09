// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

interface IAddressBook {
    function getOwners() external view returns(address[] memory);
}
