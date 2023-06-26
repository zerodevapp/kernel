import "src/validator/IValidator.sol";
import "src/abstract/KernelStorage.sol";

contract KillSwitchAction {
    IKernelValidator public immutable killSwitchValidator;
    
    constructor(IKernelValidator _killswitchValidator) {
        killSwitchValidator = _killswitchValidator;
    }

    // Function to get the wallet kernel storage
    function getKernelStorage() internal pure returns (WalletKernelStorage storage ws) {
        bytes32 storagePosition = bytes32(uint256(keccak256("zerodev.kernel")) - 1);
        assembly {
            ws.slot := storagePosition
        }
    }

    function activateKillSwitch() external {
        WalletKernelStorage storage ws = getKernelStorage();
        ws.defaultValidator = killSwitchValidator;
        getKernelStorage().disabledMode = bytes4(0xffffffff);
        getKernelStorage().lastDisabledTime = uint48(block.timestamp);
    }
}
