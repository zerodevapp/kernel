// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "account-abstraction/interfaces/IEntryPoint.sol";

struct WalletKernelStorage {
    address owner;
    address defaultPlugin;
    mapping(bytes4 => address) plugins;
    mapping(bytes4 => address) facets;
}

contract KernelStorage {
    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    IEntryPoint public immutable entryPoint;

    event Upgraded(address indexed newImplementation);

    // modifier for checking if the sender is the entrypoint or
    // the account itself
    modifier onlyFromEntryPointOrOwnerOrSelf() {
        require(
            msg.sender == address(entryPoint) || msg.sender == getKernelStorage().owner || msg.sender == address(this),
            "account: not from entrypoint or owner or self"
        );
        _;
    }

    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
        getKernelStorage().owner = address(1);
    }

    /// @notice initialize wallet kernel
    /// @dev this function should be called only once, implementation initialize is blocked by owner = address(1)
    /// @param _owner owner address
    function initialize(address _owner) external {
        WalletKernelStorage storage ws = getKernelStorage();
        require(ws.owner == address(0), "account: already initialized");
        ws.owner = _owner;
    }

    /// @notice get wallet kernel storage
    /// @dev used to get wallet kernel storage
    /// @return ws wallet kernel storage, consists of owner and nonces

    function getKernelStorage() internal pure returns (WalletKernelStorage storage ws) {
        bytes32 storagePosition = bytes32(uint256(keccak256("zerodev.kernel")) - 1);
        assembly {
            ws.slot := storagePosition
        }
    }

    function getOwner() external view returns (address) {
        return getKernelStorage().owner;
    }

    function upgradeTo(address _newImplementation) external onlyFromEntryPointOrOwnerOrSelf {
        bytes32 slot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        assembly {
            sstore(slot, _newImplementation)
        }
        emit Upgraded(_newImplementation);
    }

    function transferOwnership(address _newOwner) external onlyFromEntryPointOrOwnerOrSelf {
        getKernelStorage().owner = _newOwner;
    }

    function getNonce() public view virtual returns (uint256) {
        return entryPoint.getNonce(address(this), 0);
    }

    function getNonce(uint192 key) public view virtual returns (uint256) {
        return entryPoint.getNonce(address(this), key);
    }

    function setPlugin(bytes4 _selector, address _plugin) external onlyFromEntryPointOrOwnerOrSelf {
        getKernelStorage().plugins[_selector] = _plugin;
    }

    function setDefaultPlugin(address _plugin) external onlyFromEntryPointOrOwnerOrSelf {
        getKernelStorage().defaultPlugin = _plugin;
    }

    function addFacet(bytes4 _selector, address _facet) external onlyFromEntryPointOrOwnerOrSelf {
        getKernelStorage().facets[_selector] = _facet;
    }
}
 