pragma solidity ^0.8.0;

interface KernelERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
}

contract MockRequestor {
    function verifySignature(address kernel, bytes32 hash, bytes calldata signature) external payable returns (bool) {
        return KernelERC1271(kernel).isValidSignature(hash, signature) == 0x1626ba7e;
    }
}
