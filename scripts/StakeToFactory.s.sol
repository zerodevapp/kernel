pragma solidity ^0.8.0;

import "src/factory/KernelFactory.sol";
import "I4337/interfaces/IStakeManager.sol";
import "forge-std/Script.sol";
import "forge-std/console.sol";
contract StakeToFactory is Script {
    address constant DEPLOYER = 0x9775137314fE595c943712B0b336327dfa80aE8A;
    address constant ENTRYPOINT_0_6 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    address payable constant EXPECTED_KERNEL_ADDRESS = payable(0xf048AD83CB2dfd6037A43902a2A5Be04e53cd2Eb);
    address payable constant EXPECTED_KERNEL_FACTORY_ADDRESS = payable(0x5de4839a76cf55d0c90e2061ef4386d962E15ae3);
    function run() public {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);
        KernelFactory factory = KernelFactory(EXPECTED_KERNEL_FACTORY_ADDRESS);
        IEntryPoint entryPoint = IEntryPoint(ENTRYPOINT_0_6);
        IStakeManager.DepositInfo memory info = entryPoint.getDepositInfo(address(factory));
        if(info.stake < 1e17) {
            factory.addStake{value: 1e17}(86400);
        }
        vm.stopBroadcast();
    }
}
