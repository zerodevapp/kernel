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
    event Implementation(bytes32 indexed tagHash, address indexed implementation); 

    bytes32 immutable public create2CodeHash;
    bytes public deployByteCode;
    IEntryPoint public entryPoint;

    constructor(address _owner) {
        _initializeOwner(_owner);
        create2CodeHash = keccak256(type(Create2Proxy).creationCode);
    }

    function getImplementationAddress(bytes32 _tagHash) public view returns (address predicted) {
        bytes32 codeHash = create2CodeHash;
        bytes32 hash = keccak256(
            abi.encodePacked(bytes1(0xff), address(this), _tagHash, codeHash)
        );
        // NOTE: cast last 20 bytes of hash to address
        return address(uint160(uint(hash)));
    }

    function deployImplementation(bytes32 tagHash, bytes memory bytecode) external onlyOwner returns(address impl) {
        deployByteCode = bytecode;
        impl = address(new Create2Proxy{salt: tagHash}());
        delete deployByteCode;
        emit Implementation(tagHash, impl);
    }

    function setEntryPoint(IEntryPoint _entryPoint) external onlyOwner {
        // not setting this on constructor since we don't need stake right now
        entryPoint = _entryPoint;
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

    // in case we need to stake
    // stake functions
    function addStake(uint32 unstakeDelaySec) external payable onlyOwner {
        entryPoint.addStake{value: msg.value}(unstakeDelaySec);
    }

    function unlockStake() external onlyOwner {
        entryPoint.unlockStake();
    }

    function withdrawStake(address payable withdrawAddress) external onlyOwner {
        entryPoint.withdrawStake(withdrawAddress);
    }
}
