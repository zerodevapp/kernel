pragma solidity ^0.8.0;

import "src/factory/KernelFactory.sol";
import "src/validator/ECDSAValidator.sol";
import "src/factory/ECDSAKernelFactory.sol";
import "forge-std/Script.sol";
contract DeployKernel is Script {
    function run() public {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);
        KernelFactory factory = new KernelFactory(IEntryPoint(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789));
        ECDSAValidator validator = new ECDSAValidator();
        ECDSAKernelFactory ecdsaFactory = new ECDSAKernelFactory(factory, validator, IEntryPoint(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789));
        vm.stopBroadcast();
    }
}

