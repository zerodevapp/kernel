pragma solidity ^0.8.0;

import "src/factory/KernelFactory.sol";
import "src/validator/MultiECDSAValidator.sol";
import "src/factory/MultiECDSAKernelFactory.sol";
import "forge-std/Script.sol";
import "forge-std/console.sol";

contract DeployKernelMultiTest is Script {
    KernelFactory kernelFactory;
    MultiECDSAValidator multiECDSAValidator;
    MultiECDSAKernelFactory multiECDSAKernelFactory;

    function run(bytes32 salt) public {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);
        kernelFactory = new KernelFactory{salt: salt}(
            IEntryPoint(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789)
        );
        console.log("KernelFactory deployed at: %s", address(kernelFactory));

        multiECDSAValidator = new MultiECDSAValidator{salt: salt}();
        console.log(
            "MultiECDSAValidator deployed at: %s",
            address(multiECDSAValidator)
        );

        multiECDSAKernelFactory = new MultiECDSAKernelFactory{salt: salt}(
            kernelFactory,
            multiECDSAValidator,
            IEntryPoint(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789),
            0xf0d5D3FcBFc0009121A630EC8AB67e012117f40c
        );
        console.log(
            "MultiECDSAKernelFactory deployed at: %s",
            address(multiECDSAKernelFactory)
        );

        multiECDSAKernelFactory.addStake{value: 1}(1);

        address[] memory owners = new address[](1);
        owners[0] = address(0xaD6442a1b5A9D5a25eDE2f8dC3A99C7038b95CD5);

        multiECDSAKernelFactory.setOwners(owners);

        vm.stopBroadcast();
    }
}
