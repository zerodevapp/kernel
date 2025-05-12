pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {EntryPointLib} from "./utils/EntryPointLib.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Kernel} from "src/Kernel.sol";
import {KernelFactory} from "src/KernelFactory.sol";

contract MockValidator {
    event MockInstall(bytes data);
    event MockUninstall(bytes data);

    function onInstall(bytes calldata data) external payable {
        emit MockInstall(data);
    }

    function onUninstall(bytes calldata data) external payable {
        emit MockUninstall(data);
    }
}

contract KernelTest is Test {
    IEntryPoint ep;
    KernelFactory factory;
    MockValidator mockValidator;
    Kernel kernel;

    function setUp() external {
        ep = EntryPointLib.deploy();
        factory = new KernelFactory(ep);
        mockValidator = new MockValidator();
        _initialize();
    }

    function _initialize() internal {
        kernel = factory.deploy(abi.encode("Kernel Test"));
    }

    function test_deploy() external {
        Kernel k = factory.deploy(hex"");
    }

    function test_install_validator() external {
        kernel.installModule(1, address(mockValidator), abi.encode(hex"deadbeef", "InternalData"));
    }
}
