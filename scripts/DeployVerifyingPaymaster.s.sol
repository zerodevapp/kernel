pragma solidity ^0.8.0;

import "src/paymaster/VerifyingPaymaster.sol";
import "forge-std/Script.sol";
import "forge-std/console.sol";
contract DeployVerifyingPaymaster is Script {
    address constant DEPLOYER = 0x9fD431b7703f94289Ba02034631dcC302717805B;
    address constant ENTRYPOINT_0_6 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    function run() public {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);
        address verifyingSigner = 0xBa9CFe6A44979ADdDbF9F4342c65c4Da9C5b207B;
        VerifyingPaymaster paymaster = new VerifyingPaymaster{salt:"0x31"}(IEntryPoint(ENTRYPOINT_0_6), verifyingSigner);
        console.log("paymaster address: %s", address(paymaster));
        vm.stopBroadcast();
    }
}

// forge script scripts/DeployVerifyingPaymaster.s.sol --chain-id 5 --rpc-url https://goerli.infura.io/v3/087f8478a2174ebd94cc19b9501362a4 --etherscan-api-key 2QTNEVQ2RKXIYS4SGRM8NVCVBB9V1JFWD6  --broadcast