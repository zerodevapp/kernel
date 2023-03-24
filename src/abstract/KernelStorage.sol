// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "account-abstraction/interfaces/IEntryPoint.sol";

struct WalletKernelStorage {
    address owner;
    uint256 nonce;
}

contract KernelStorage {
    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    IEntryPoint public immutable entryPoint;

    event Upgraded(address indexed newImplementation);

    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
        getKernelStorage().owner = address(1);
    }
    /// @notice get wallet kernel storage
    /// @dev used to get wallet kernel storage
    /// @return ws wallet kernel storage, consists of owner and nonces

    function getKernelStorage() internal pure returns (WalletKernelStorage storage ws) {
        bytes32 storagePosition = bytes32(uint256(keccak256("zero-dev.kernel")) - 1);
        assembly {
            ws.slot := storagePosition
        }
    }

    function getOwner() external view returns (address) {
        return getKernelStorage().owner;
    }

    function getNonce() external view returns (uint256) {
        return getKernelStorage().nonce;
    }

    function upgradeTo(address _newImplementation) external {
        require(
            msg.sender == address(entryPoint) || msg.sender == getKernelStorage().owner,
            "account: not from entrypoint or owner"
        );
        bytes32 slot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        assembly {
            sstore(slot, _newImplementation)
        }
        emit Upgraded(_newImplementation);
    }
}
