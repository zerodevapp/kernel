pragma solidity ^0.8.0;

import "src/factory/MultiECDSAFactoryPatch.sol";
import "src/validator/MultiECDSAValidatorNew.sol";
import "src/Kernel.sol";
import "forge-std/Script.sol";
import "forge-std/console.sol";

contract DeployMultiECDSAFactoryPatchTest is Script {
    function run(bytes32 salt) public {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);

        Kernel kernelImplementation = new Kernel{salt: salt}(
            IEntryPoint(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789)
        );
        console.log("Kernel deployed at: %s", address(kernelImplementation));

        MultiECDSAValidatorNew multiECDSAValidatorNew = new MultiECDSAValidatorNew{
                salt: salt
            }();
        console.log(
            "MultiECDSAValidatorNew deployed at: %s",
            address(multiECDSAValidatorNew)
        );

        MultiECDSAFactoryPatch multiECDSAFactoryPatch = new MultiECDSAFactoryPatch{
                salt: salt
            }(
                0xf0d5D3FcBFc0009121A630EC8AB67e012117f40c,
                IEntryPoint(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789),
                kernelImplementation,
                multiECDSAValidatorNew
            );
        console.log(
            "MultiECDSAFactoryPatch deployed at: %s",
            address(multiECDSAFactoryPatch)
        );

        multiECDSAFactoryPatch.setImplementation(
            address(kernelImplementation),
            true
        );

        address[] memory owners = new address[](1);
        owners[0] = address(0xaD6442a1b5A9D5a25eDE2f8dC3A99C7038b95CD5);

        multiECDSAFactoryPatch.setOwners(owners);

        multiECDSAFactoryPatch.addStake{value: 1}(1);

        vm.stopBroadcast();
    }
}
