pragma solidity ^0.8.0;

bytes32 constant ERC1967_IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

contract BootLoader {
    address immutable THIS;

    constructor() {
        THIS = address(this);
    }

    function boot(bytes calldata initData, bytes calldata bootData, bytes calldata bootSig) external {
        require(address(this) != THIS, "BootLoader: boot can only be called by a proxy");
        (address implementation) = address(bytes20(initData[0:20]));
        assembly {
            sstore(ERC1967_IMPLEMENTATION_SLOT, implementation)
        }
        (bool success,) = implementation.delegatecall(initData[20:]);
        require(success, "BootLoader: init failed");
    }
}
