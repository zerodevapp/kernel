pragma solidity ^0.8.0;

contract Create2Proxy {
    constructor() {
        bytes memory bytecode = ICreate2Factory(msg.sender).deployByteCode();
        assembly {
            return (add(bytecode, 0x20), mload(bytecode))
        }
    }
}

interface ICreate2Factory {
    function deployByteCode() external view returns (bytes memory);
}
