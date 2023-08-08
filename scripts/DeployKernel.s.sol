pragma solidity ^0.8.0;

import "src/factory/KernelFactory.sol";
import "src/validator/ECDSAValidator.sol";
import "account-abstraction/interfaces/IStakeManager.sol";
import "forge-std/Script.sol";
import "forge-std/console.sol";
contract DeployKernel is Script {
    address constant DEPLOYER = 0x9775137314fE595c943712B0b336327dfa80aE8A;
    address constant ENTRYPOINT_0_6 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    address constant EXPECTED_KERNEL_ADDRESS = 0xD2063bE7C610eb55492C05385743edDbf5b6B951;
    address constant EXPECTED_KERNEL_FACTORY_ADDRESS = 0x85DF6Dc686FBDcAc7da61651D116fc71B2246B50;
    function run() public {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);
        if(EXPECTED_KERNEL_ADDRESS.code.length == 0){
            Kernel kernel = new Kernel{salt:0}(IEntryPoint(ENTRYPOINT_0_6));
            console.log("Kernel address: %s", address(kernel));
        } else {
            console.log("Kernel address: %s", address(EXPECTED_KERNEL_ADDRESS));
        }
        KernelFactory factory;
        if(EXPECTED_KERNEL_FACTORY_ADDRESS.code.length == 0){
            factory = new KernelFactory{salt:0}(DEPLOYER, IEntryPoint(ENTRYPOINT_0_6));
            console.log("KernelFactory address: %s", address(factory));
        } else {
            factory = KernelFactory(EXPECTED_KERNEL_FACTORY_ADDRESS);
            console.log("KernelFactory address: %s", address(factory));
        }
        IEntryPoint entryPoint = IEntryPoint(ENTRYPOINT_0_6);
        IStakeManager.DepositInfo memory info = entryPoint.getDepositInfo(address(factory));
        if(info.stake == 0) {
            console.log("Staking 1 wei to factory");
            factory.addStake{value:1}(1);
        }
        vm.stopBroadcast();
    }
}

