pragma solidity ^0.8.0;

import "src/factory/KernelFactory.sol";
import "forge-std/Script.sol";

import "./deterministic/ECDSAValidator.s.sol";
import "./deterministic/Factory.s.sol";
import "./deterministic/SessionKey.s.sol";
import "./deterministic/Kernel2_2.s.sol";
import "./deterministic/Kernel2_3.s.sol";
import "./deterministic/FclWebAuthNValidator.s.sol";

contract DeployDeterministic is Script {
    address constant DEPLOYER = 0x9775137314fE595c943712B0b336327dfa80aE8A;

    function run() external {
        vm.startBroadcast(DEPLOYER);
        KernelFactory factory = KernelFactory(payable(FactoryDeploy.deploy()));

        ECDSAValidatorDeploy.deploy();
        SessionKeyDeploy.deploy();

        //(address k22, address k22lite) = Kernel_2_2_Deploy.deploy();

        //if(!factory.isAllowedImplementation(k22)) {
        //    factory.setImplementation(k22, true);
        //}
        //if(!factory.isAllowedImplementation(k22lite)) {
        //    factory.setImplementation(k22lite, true);
        //}

        (address k23, address k23lite) = Kernel_2_3_Deploy.deploy();
        if (!factory.isAllowedImplementation(k23)) {
            factory.setImplementation(k23, true);
        }
        if (!factory.isAllowedImplementation(k23lite)) {
            factory.setImplementation(k23lite, true);
        }

        // Deploy the webauthn fcl validators
        FclWebAuthnValidatorDeploy.deployWebAuthnFclVerifier();

        vm.stopBroadcast();
    }
}
