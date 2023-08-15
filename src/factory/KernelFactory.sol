// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./AdminLessERC1967Factory.sol";

import "openzeppelin-contracts/contracts/utils/Create2.sol";
import "src/Kernel.sol";
import "src/validator/ECDSAValidator.sol";
import "solady/auth/Ownable.sol";
import "src/utils/Create2Flag.sol";
import "src/utils/Create2Proxy.sol";

contract KernelFactory is AdminLessERC1967Factory, Ownable {
    error InvalidImplementation();
    bytes public deployByteCode;

    constructor(address _owner) {
        _initializeOwner(_owner);
    }

    function getImplementationAddress(bytes32 _tagHash) public view returns (address predicted) {
        bytes memory code = type(Create2Proxy).creationCode;
        bytes32 hash = keccak256(
            abi.encodePacked(bytes1(0xff), address(this), _tagHash, keccak256(code))
        );
        // NOTE: cast last 20 bytes of hash to address
        return address(uint160(uint(hash)));
    }

    function deployImplementation(bytes32 tagHash, bytes memory bytecode) external onlyOwner returns(address) {
        deployByteCode = bytecode;
        return address(new Create2Proxy{salt: tagHash}());
    }

    function createAccount(bytes32 _tagHash, bytes calldata _data, uint256 _index)
        external
        payable
        returns (address proxy)
    {
        address impl = getImplementationAddress(_tagHash);
        if(impl.code.length == 0) {
            revert InvalidImplementation();
        }
        bytes32 salt = bytes32(uint256(keccak256(abi.encodePacked(_data, _index))) & type(uint96).max);
        proxy = deployDeterministicAndCall(impl, salt, _data);
    }

    function getAccountAddress(bytes calldata _data, uint256 _index) public view returns (address) {
        bytes32 salt = bytes32(uint256(keccak256(abi.encodePacked(_data, _index))) & type(uint96).max);
        return predictDeterministicAddress(salt);
    }
}
