pragma solidity ^0.8.0;

import "src/KernelFactory.sol";
import "forge-std/Script.sol";
contract DeployKernel is Script {
    function run() public {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);
        KernelFactory factory = new KernelFactory(IEntryPoint(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789));
        vm.stopBroadcast();
    }
}

