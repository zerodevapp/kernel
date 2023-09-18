pragma solidity ^0.8.0;

import "aa-benchmark/src/TestBase.sol";
import {Kernel,KernelStorage} from "src/Kernel.sol";
import {KernelFactory} from "src/factory/KernelFactory.sol";
import {ECDSAValidator} from "src/validator/ECDSAValidator.sol";
contract Benchmark is AAGasProfileBase {
    Kernel kernelImpl;
    KernelFactory factory;
    ECDSAValidator validator;
    address factoryOwner;

    function setUp() external {
        factoryOwner = address(0);
        initializeTest("kernelv2_1");
        factory = new KernelFactory(factoryOwner, entryPoint);
        kernelImpl = new Kernel(entryPoint);
        vm.startPrank(factoryOwner);
        factory.setImplementation(address(kernelImpl), true);
        vm.stopPrank();
        validator = new ECDSAValidator();
        setAccount();
    }

    function fillData(address _to, uint256 _value, bytes memory _data) internal override returns (bytes memory) {
        return abi.encodeWithSelector(Kernel.execute.selector, _to, _value, _data, uint8(0));
    }

    function createAccount(address _owner) internal override {
        if (address(account).code.length == 0) {
            factory.createAccount(
                address(kernelImpl),
                abi.encodeWithSelector(KernelStorage.initialize.selector, validator, abi.encodePacked(_owner)),
                0
            );
        }
    }

    function getAccountAddr(address _owner) internal override returns (IAccount) {
        return IAccount(
            factory.getAccountAddress(
                abi.encodeWithSelector(KernelStorage.initialize.selector, validator, abi.encodePacked(_owner)), 0
            )
        );
    }

    function getInitCode(address _owner) internal override returns (bytes memory) {
        return abi.encodePacked(
            address(factory),
            abi.encodeWithSelector(
                factory.createAccount.selector,
                kernelImpl,
                abi.encodeWithSelector(KernelStorage.initialize.selector, validator, abi.encodePacked(_owner)),
                0
            )
        );
    }

    function getSignature(UserOperation memory _op) internal override returns (bytes memory) {
        return abi.encodePacked(bytes4(0x00000000), signUserOpHash(key, _op));
    }
}
