pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {EntryPointLib} from "./utils/EntryPointLib.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Kernel} from "src/Kernel.sol";
import {KernelFactory} from "src/KernelFactory.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";

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

contract MockCallee {
    uint256 public bar;
    string public data;

    event Lorem();

    error Haha();

    function foo() external {
        bar++;
        emit Lorem();
    }

    function lorem() external {
        data = "lorem ipsum";
    }

    function forceRevert() external {
        revert Haha();
    }
}

struct Call {
    address target;
    uint256 value;
    bytes data;
}

contract KernelTest is Test {
    IEntryPoint ep;
    KernelFactory factory;
    MockValidator mockValidator;
    Kernel kernel;
    MockCallee callee;
    address executor;

    modifier unitTest() {
        vm.startPrank(address(ep));
        _;
        vm.stopPrank();
    }

    modifier unitTestExecutor() {
        vm.startPrank(address(executor));
        _;
        vm.stopPrank();
    }

    function setUp() external {
        ep = EntryPointLib.deploy();
        factory = new KernelFactory(ep);
        mockValidator = new MockValidator();
        callee = new MockCallee();
        executor = makeAddr("Executor");
        _initialize();
    }

    function _initialize() internal {
        kernel = factory.deploy(abi.encode("Kernel Test"));

        vm.startPrank(address(ep));
        kernel.installModule(2, executor, abi.encode(hex"", ""));
        vm.stopPrank();
    }

    function test_deploy() external unitTest {
        Kernel k = factory.deploy(hex"");
    }

    function test_install_validator() external unitTest {
        kernel.installModule(1, address(mockValidator), abi.encode(hex"deadbeef", "InternalData"));
    }

    function test_execute() external unitTest {
        vm.expectEmit(address(callee));
        emit MockCallee.Lorem();
        kernel.execute(
            bytes32(0), abi.encodePacked(address(callee), uint256(0), abi.encodeWithSelector(MockCallee.foo.selector))
        );
        assertEq(callee.bar(), 1);
    }

    function test_execute_fail() external unitTest {
        vm.expectRevert(MockCallee.Haha.selector);
        kernel.execute(
            bytes32(0),
            abi.encodePacked(address(callee), uint256(0), abi.encodeWithSelector(MockCallee.forceRevert.selector))
        );
    }

    function test_execute_fail_try() external unitTest {
        kernel.execute(
            LibERC7579.encodeMode(bytes1(0x00), bytes1(0x01), bytes4(0), bytes22(0)),
            abi.encodePacked(address(callee), uint256(0), abi.encodeWithSelector(MockCallee.forceRevert.selector))
        );
    }

    function test_execute_batch() external unitTest {
        Call[] memory calls = new Call[](2);
        calls[0] = Call({target: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.foo.selector)});
        calls[1] = Call({target: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.lorem.selector)});
        assertEq(callee.data(), "");
        vm.expectEmit(address(callee));
        emit MockCallee.Lorem();
        kernel.execute(LibERC7579.encodeMode(bytes1(0x01), bytes1(0x00), bytes4(0), bytes22(0)), abi.encode(calls));
        assertEq(callee.bar(), 1);
        assertEq(callee.data(), "lorem ipsum");
    }

    function test_execute_batch_fail() external unitTest {
        Call[] memory calls = new Call[](2);
        calls[0] = Call({target: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.foo.selector)});
        calls[1] =
            Call({target: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.forceRevert.selector)});
        assertEq(callee.data(), "");
        vm.expectRevert(MockCallee.Haha.selector);
        kernel.execute(LibERC7579.encodeMode(bytes1(0x01), bytes1(0x00), bytes4(0), bytes22(0)), abi.encode(calls));
    }

    function test_execute_batch_fail_try() external unitTest {
        Call[] memory calls = new Call[](2);
        calls[0] = Call({target: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.foo.selector)});
        calls[1] =
            Call({target: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.forceRevert.selector)});
        assertEq(callee.data(), "");
        kernel.execute(LibERC7579.encodeMode(bytes1(0x01), bytes1(0x01), bytes4(0), bytes22(0)), abi.encode(calls));
        assertEq(callee.bar(), 1);
    }

    function test_execute_delegatecall() external unitTest {
        vm.expectEmit(address(kernel));
        emit MockCallee.Lorem();
        kernel.execute(
            LibERC7579.encodeMode(bytes1(0xff), bytes1(0x00), bytes4(0), bytes22(0)),
            abi.encodePacked(address(callee), abi.encodeWithSelector(MockCallee.foo.selector))
        );
    }

    function test_execute_delegatecall_fail() external unitTest {
        vm.expectRevert(MockCallee.Haha.selector);
        kernel.execute(
            LibERC7579.encodeMode(bytes1(0xff), bytes1(0x00), bytes4(0), bytes22(0)),
            abi.encodePacked(address(callee), abi.encodeWithSelector(MockCallee.forceRevert.selector))
        );
    }

    function test_execute_delegatecall_fail_try() external unitTest {
        kernel.execute(
            LibERC7579.encodeMode(bytes1(0xff), bytes1(0x01), bytes4(0), bytes22(0)),
            abi.encodePacked(address(callee), abi.encodeWithSelector(MockCallee.forceRevert.selector))
        );
    }

    function test_execute_from_executor() external unitTestExecutor {
        vm.expectEmit(address(callee));
        emit MockCallee.Lorem();
        kernel.executeFromExecutor(
            bytes32(0), abi.encodePacked(address(callee), uint256(0), abi.encodeWithSelector(MockCallee.foo.selector))
        );
        assertEq(callee.bar(), 1);
    }

    function test_execute_batch_from_executor() external unitTestExecutor {
        Call[] memory calls = new Call[](2);
        calls[0] = Call({target: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.foo.selector)});
        calls[1] = Call({target: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.lorem.selector)});
        assertEq(callee.data(), "");
        vm.expectEmit(address(callee));
        emit MockCallee.Lorem();
        kernel.executeFromExecutor(
            LibERC7579.encodeMode(bytes1(0x01), bytes1(0x00), bytes4(0), bytes22(0)), abi.encode(calls)
        );
        assertEq(callee.bar(), 1);
        assertEq(callee.data(), "lorem ipsum");
    }

    function test_execute_delegatecall_from_executor() external unitTestExecutor {
        vm.expectEmit(address(kernel));
        emit MockCallee.Lorem();
        kernel.executeFromExecutor(
            LibERC7579.encodeMode(bytes1(0xff), bytes1(0x00), bytes4(0), bytes22(0)),
            abi.encodePacked(address(callee), abi.encodeWithSelector(MockCallee.foo.selector))
        );
    }
}
