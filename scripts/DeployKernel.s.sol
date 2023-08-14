pragma solidity ^0.8.0;

import "src/factory/KernelFactory.sol";
import "src/validator/ECDSAValidator.sol";
import "account-abstraction/interfaces/IStakeManager.sol";
import "forge-std/Script.sol";
import "forge-std/console.sol";
contract DeployKernel is Script {
    address constant DEPLOYER = 0x9775137314fE595c943712B0b336327dfa80aE8A;
    address constant ENTRYPOINT_0_6 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    //  Kernel address: 0xf048AD83CB2dfd6037A43902a2A5Be04e53cd2Eb
    // KernelFactory address: 0xA3A415a987b1Ae1afe28Ab77F9e9CB1D1DBb4D69
    address constant EXPECTED_KERNEL_ADDRESS = 0xf048AD83CB2dfd6037A43902a2A5Be04e53cd2Eb;
    address constant EXPECTED_KERNEL_FACTORY_ADDRESS = 0xA3A415a987b1Ae1afe28Ab77F9e9CB1D1DBb4D69;
    function run() public {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);
        Kernel kernel
        if(EXPECTED_KERNEL_ADDRESS.code.length == 0 ){
            kernel = new Kernel{salt:0}(IEntryPoint(ENTRYPOINT_0_6));
            console.log("Kernel address: %s", address(kernel));
        } else {
            kernel = Kernel(EXPECTED_KERNEL_ADDRESS);
        }
        KernelFactory factory;
        if(EXPECTED_KERNEL_FACTORY_ADDRESS.code.length == 0){
            factory = new KernelFactory{salt:0}(DEPLOYER, IEntryPoint(ENTRYPOINT_0_6));
            console.log("KernelFactory address: %s", address(factory));
        } else {
            factory = KernelFactory(EXPECTED_KERNEL_FACTORY_ADDRESS);
        }
        if(factory.isAllowedImplementation(address(kernel)) == false) {
            console.log("Registering kernel implementation");
            factory.setImplementation(address(kernel), true);
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

