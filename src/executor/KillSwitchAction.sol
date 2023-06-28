pragma solidity ^0.8.18;

import "src/validator/IValidator.sol";
import "src/validator/KillSwitchValidator.sol";
import "src/abstract/KernelStorage.sol";

contract KillSwitchAction {
    KillSwitchValidator public immutable killSwitchValidator;
    
    constructor(KillSwitchValidator _killswitchValidator) {
        killSwitchValidator = _killswitchValidator;
    }

    // Function to get the wallet kernel storage
    function getKernelStorage() internal pure returns (WalletKernelStorage storage ws) {
        bytes32 storagePosition = bytes32(uint256(keccak256("zerodev.kernel")) - 1);
        assembly {
            ws.slot := storagePosition
        }
    }

    function toggleKillSwitch() external {
        WalletKernelStorage storage ws = getKernelStorage();
        if(address(ws.defaultValidator) != address(killSwitchValidator)) {
            // this means it is not activated
            ws.defaultValidator = killSwitchValidator;
            getKernelStorage().disabledMode = bytes4(0xffffffff);
            getKernelStorage().lastDisabledTime = uint48(block.timestamp);
        } else {
            (address guardian, IKernelValidator prevValidator, , bytes4 prevDisableMode)  = killSwitchValidator.killSwitchValidatorStorage(address(this));
            // this means it is activated
            ws.defaultValidator = prevValidator;
            getKernelStorage().disabledMode = prevDisableMode;
        }
    }
}
