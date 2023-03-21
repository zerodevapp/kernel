// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

struct WalletKernelStorage {
    address owner;
    uint256 nonce;
}

contract KernelStorage {
    /// @notice get wallet kernel storage
    /// @dev used to get wallet kernel storage
    /// @return ws wallet kernel storage, consists of owner and nonces
    function getKernelStorage() internal pure returns (WalletKernelStorage storage ws) {
        bytes32 storagePosition = bytes32(uint256(keccak256("zero-dev.kernel")) - 1);
        assembly {
            ws.slot := storagePosition
        }
    }
}