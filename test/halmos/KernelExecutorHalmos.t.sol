pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {MockCallee} from "../mock/MockCallee.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

contract KernelExecutorHalmos is SymTest, Test {
    MockCallee callee;
    KernelUUPS kernel;
    address executor;

    function setUp() external {
        callee = new MockCallee();
        address entryPoint = makeAddr("EntryPoint");
        kernel = new KernelUUPS(IEntryPoint(entryPoint));
        executor = address(0xdeadbeef);
        vm.startPrank(entryPoint);
        kernel.installModule(2, executor, abi.encode(hex"", ""));
        vm.stopPrank();
    }

    function check_execute_from_executor_return0() external {
        execute_from_executor(0);
    }

    function check_execute_from_executor_return8() external {
        execute_from_executor(8);
    }

    function check_execute_from_executor_return32() external {
        execute_from_executor(32);
    }

    function check_execute_from_executor_return64() external {
        execute_from_executor(64);
    }

    function check_execute_from_executor_return256() external {
        execute_from_executor(256);
    }

    function check_execute_from_executor_return1024() external {
        execute_from_executor(1024);
    }

    function check_execute_from_executor_return4096() external {
        execute_from_executor(4096);
    }

    function execute_from_executor(uint256 length) internal {
        bytes memory data = svm.createBytes(length, "data");
        vm.startPrank(executor);
        bytes[] memory ret = kernel.executeFromExecutor(
            bytes32(0),
            abi.encodePacked(address(callee), uint256(0), abi.encodeWithSelector(MockCallee.ret.selector, data))
        );
        assertEq(ret.length, 1);
        bytes memory actual = abi.decode(ret[0], (bytes));
        assertEq(keccak256(actual), keccak256(data));
    }
}
