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

    function checkExecuteFromExecutorReturn0() external {
        _executeFromExecutor(0);
    }

    function checkExecuteFromExecutorReturn8() external {
        _executeFromExecutor(8);
    }

    function checkExecuteFromExecutorReturn32() external {
        _executeFromExecutor(32);
    }

    function checkExecuteFromExecutorReturn64() external {
        _executeFromExecutor(64);
    }

    function checkExecuteFromExecutorReturn256() external {
        _executeFromExecutor(256);
    }

    function checkExecuteFromExecutorReturn1024() external {
        _executeFromExecutor(1024);
    }

    function checkExecuteFromExecutorReturn4096() external {
        _executeFromExecutor(4096);
    }

    function _executeFromExecutor(uint256 length) internal {
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
