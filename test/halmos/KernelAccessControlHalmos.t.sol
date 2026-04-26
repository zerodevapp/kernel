pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Kernel} from "src/Kernel.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {KernelImmutableECDSA} from "src/KernelImmutableECDSA.sol";
import {KernelFactory} from "src/KernelFactory.sol";
import {Install} from "src/types/Structs.sol";
import {Unauthorized} from "src/types/Error.sol";
import {EntryPointLib} from "../utils/EntryPointLib.sol";
import {MockValidator} from "../mock/MockValidator.sol";
import {MockExecutor} from "../mock/MockExecutor.sol";

contract KernelAccessControlHalmos is SymTest, Test {
    Kernel private kernel;
    IEntryPoint private ep;
    MockExecutor private executor;

    function setUp() external {
        ep = EntryPointLib.deploy();
        KernelUUPS uups = new KernelUUPS(ep);
        KernelImmutableECDSA immutableEcdsa = new KernelImmutableECDSA(ep);
        KernelFactory factory = new KernelFactory(uups, immutableEcdsa);
        MockValidator rootValidator = new MockValidator();
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({moduleType: 1, module: address(rootValidator), moduleData: hex"", internalData: hex""});
        kernel = factory.deploy(pkgs, 0);

        executor = new MockExecutor();
        vm.startPrank(address(ep));
        kernel.installModule(2, address(executor), abi.encode(hex"deadbeef", hex""));
        vm.stopPrank();
    }

    function checkInstallModuleRequiresEntryPoint() external {
        address caller = address(uint160(uint256(keccak256("caller"))));
        vm.startPrank(caller);
        vm.expectRevert(Unauthorized.selector);
        kernel.installModule(4, address(new MockExecutor()), abi.encode(hex"", hex""));
        vm.stopPrank();
    }

    function checkExecuteRequiresEntryPoint() external {
        address caller = address(uint160(uint256(keccak256("caller"))));
        vm.startPrank(caller);
        vm.expectRevert(Unauthorized.selector);
        kernel.execute(bytes32(0), abi.encodePacked(address(kernel), uint256(0), kernel.accountId.selector));
        vm.stopPrank();
    }

    function checkExecuteFromExecutorRequiresInstalledExecutor() external {
        address caller = address(uint160(uint256(keccak256("caller"))));
        vm.startPrank(caller);
        vm.expectRevert(Unauthorized.selector);
        kernel.executeFromExecutor(bytes32(0), abi.encodePacked(address(kernel), uint256(0), kernel.accountId.selector));
        vm.stopPrank();
    }
}
