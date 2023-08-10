pragma solidity ^0.8.0;

import "src/factory/KernelFactory.sol";
import "src/validator/SocialRecoveryValidator.sol";
import "src/factory/RecoveryKernelFactory.sol";
import "src/validator/ERC165SessionKeyValidator.sol";
import "forge-std/Script.sol";
import "forge-std/console.sol";

contract DeploySocialRecovery is Script {
    address internal constant DETERMINISTIC_CREATE2_FACTORY = 0x7A0D94F55792C434d74a40883C6ed8545E406D12;
    function run() public {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);
        SocialRecoveryValidator action = new SocialRecoveryValidator();
                
        bytes memory bytecode = type(SocialRecoveryValidator).creationCode; 
        (bool success, bytes memory returnData) = DETERMINISTIC_CREATE2_FACTORY.call(abi.encodePacked(bytecode, abi.encode(action)));
        require(success, "Failed to deploy SocialRecoveryValidator");
        address validator = address(bytes20(returnData));
        console.log("SocialRecoveryValidator deployed at: %s", validator);
        vm.stopBroadcast();
    }
}