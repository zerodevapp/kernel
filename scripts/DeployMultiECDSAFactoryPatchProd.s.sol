pragma solidity ^0.8.0;

import "src/factory/MultiECDSAFactoryPatch.sol";
import "src/validator/MultiECDSAValidatorNew.sol";
import "forge-std/Script.sol";
import "forge-std/console.sol";

contract DeployMultiECDSAFactoryPatchProd is Script {
    MultiECDSAValidatorNew multiECDSAValidatorNew;
    MultiECDSAFactoryPatch multiECDSAFactoryPatch;

    function run(bytes32 salt) public {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);
        multiECDSAValidatorNew = new MultiECDSAValidatorNew{salt: salt}();
        console.log(
            "MultiECDSAValidatorNew deployed at: %s",
            address(multiECDSAValidatorNew)
        );

        multiECDSAFactoryPatch = new MultiECDSAFactoryPatch{salt: salt}(
            0xf0d5D3FcBFc0009121A630EC8AB67e012117f40c,
            IEntryPoint(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789),
            multiECDSAValidatorNew
        );
        console.log(
            "MultiECDSAFactoryPatch deployed at: %s",
            address(multiECDSAFactoryPatch)
        );

        multiECDSAFactoryPatch.addStake{value: 1}(1);

        address[] memory owners = new address[](1);
        owners[0] = address(0xdD664b8A02d3B13C0bdfB1878CbE66aA53B2de06);

        multiECDSAFactoryPatch.setOwners(owners);

        multiECDSAFactoryPatch.transferOwnership(
            0x74427681c620DE258Aa53a382d6a4C865738A06C
        );

        vm.stopBroadcast();
    }
}
