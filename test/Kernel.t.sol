pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {EntryPointLib} from "./utils/EntryPointLib.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Kernel} from "src/Kernel.sol";
import {SelectorManager} from "src/core/SelectorManager.sol";
import {KernelFactory} from "src/KernelFactory.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";
import {Install} from "src/types/Structs.sol";
import {MockFallback} from "./mock/MockFallback.sol";
import {MockExecutor} from "./mock/MockExecutor.sol";
import {MockValidator} from "./mock/MockValidator.sol";
import {MockHook} from "./mock/MockHook.sol";
import {IHook} from "src/interfaces/IERC7579Modules.sol";
import {CallType} from "src/types/Types.sol";
import "src/types/Error.sol";

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
    MockFallback mockFallback;
    address executor;
    address payable beneficiary;

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

    modifier entryPointTest() {
        _;
    }

    function setUp() external {
        ep = EntryPointLib.deploy();
        factory = new KernelFactory(ep);
        mockValidator = new MockValidator();
        callee = new MockCallee();
        executor = makeAddr("Executor");
        mockFallback = new MockFallback();
        beneficiary = payable(makeAddr("Beneficiary"));
        _initialize();
    }

    function _initialize() internal {
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({moduleType: 1, module: address(mockValidator), moduleData: hex"", internalData: hex""});
        kernel = factory.deploy(pkgs, 0);
        vm.deal(address(kernel), 1e18);

        vm.startPrank(address(ep));
        kernel.installModule(2, executor, abi.encode(hex"", ""));
        vm.stopPrank();
    }

    function encodeNonce(bool replayableUserOp, bool enableFlag, bool replayableEnable, bytes1 vType, bytes20 vId) internal returns(uint256 nonce) {
        uint8 uMode = 0;
        if(replayableEnable) {
            uMode += 2**6;
        }
        if(enableFlag) {
            uMode += 2**3;
        }
        if(replayableEnable) {
            uMode +=  2**2;
        }
        uint192 key = uint192(bytes24(abi.encodePacked(uMode, vType, vId, bytes2(0x00))));
        return ep.getNonce(address(kernel), key);
    }

    function test_userop() external entryPointTest {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce : encodeNonce(false, false, false, bytes1(0), bytes20(0)),
            initCode : hex"",
            callData : abi.encodeWithSelector(Kernel.execute.selector, bytes32(0), abi.encodePacked(address(callee), MockCallee.foo.selector)),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))), // TODO make this dynamic
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        mockValidator.sudoSetSuccess(true);
        ep.handleOps(ops, beneficiary);
    }

    function test_deploy() external unitTest {
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({moduleType: 1, module: address(mockValidator), moduleData: hex"", internalData: hex""});
        Kernel k = factory.deploy(pkgs, 1);
    }

    function test_install_executor_oninstall_success() external unitTest {
        address newEx = address(new MockExecutor());
        kernel.installModule(2, newEx, abi.encode(hex"deadbeef", ""));
        assertEq(address(kernel.executorConfig(newEx).hook), address(1));
    }

    function test_install_executor_oninstall_fail() external unitTest {
        address newEx = makeAddr("New Executor");
        kernel.installModule(2, newEx, abi.encode(hex"", ""));
        assertEq(address(kernel.executorConfig(newEx).hook), address(1));
    }

    function test_uninstall_executor_onuninstall_success() external unitTest {
        address newEx = address(new MockExecutor());
        kernel.installModule(2, newEx, abi.encode(hex"deadbeef", ""));
        assertEq(address(kernel.executorConfig(newEx).hook), address(1));
        kernel.uninstallModule(2, newEx, abi.encode(hex"", hex""));
        assertEq(address(kernel.executorConfig(newEx).hook), address(0));
    }

    function test_uninstall_executor_onuninstall_fail() external unitTest {
        address newEx = makeAddr("New Executor");
        kernel.installModule(2, newEx, abi.encode(hex"", ""));
        assertEq(address(kernel.executorConfig(newEx).hook), address(1));
        kernel.uninstallModule(2, newEx, abi.encode(hex"", hex""));
        assertEq(address(kernel.executorConfig(newEx).hook), address(0));
    }

    function test_install_hook() external unitTest {
        MockHook mockHook = new MockHook();
        kernel.installModule(4, address(mockHook), abi.encode(hex"", ""));
    }

    function test_uninstall_hook() external unitTest {
        MockHook mockHook = new MockHook();
        kernel.installModule(4, address(mockHook), abi.encode(hex"", ""));
        kernel.uninstallModule(4, address(mockHook), abi.encode(hex"", ""));
    }

    function test_install_validator() external unitTest {
        kernel.installModule(1, address(mockValidator), abi.encode(hex"deadbeef", "InternalData"));
    }

    function test_install_selector_call() external unitTest {
        kernel.installModule(
            3,
            address(mockFallback),
            abi.encode(
                hex"deadbeef", abi.encodePacked(MockFallback.fallbackFunction.selector, bytes1(0x00), address(1))
            )
        );
        vm.expectEmit(address(mockFallback));
        emit MockFallback.Foobar();
        uint256 res = MockFallback(address(kernel)).fallbackFunction(10);
        assertEq(res, 100);
        SelectorManager.SelectorConfig memory c = kernel.selectorConfig(MockFallback.fallbackFunction.selector);
        assertEq(address(c.target), address(mockFallback));
        assertEq(address(c.hook), address(1));
        assertTrue(c.callType == CallType.wrap(bytes1(0x00)));
    }

    function test_install_selector_call_withhook() external unitTest {
        MockHook mockHook = new MockHook();
        kernel.installModule(4, address(mockHook), abi.encode(hex"", ""));
        kernel.installModule(
            3,
            address(mockFallback),
            abi.encode(
                hex"deadbeef", abi.encodePacked(MockFallback.fallbackFunction.selector, bytes1(0x00), address(mockHook))
            )
        );
        vm.expectEmit(address(mockFallback));
        emit MockFallback.Foobar();
        uint256 res = MockFallback(address(kernel)).fallbackFunction(10);
        assertEq(res, 100);
        SelectorManager.SelectorConfig memory c = kernel.selectorConfig(MockFallback.fallbackFunction.selector);
        assertEq(address(c.target), address(mockFallback));
        assertEq(address(c.hook), address(mockHook));
        assertTrue(c.callType == CallType.wrap(bytes1(0x00)));
    }

    function test_uninstall_selector_call() external unitTest {
        kernel.installModule(
            3,
            address(mockFallback),
            abi.encode(
                hex"deadbeef", abi.encodePacked(MockFallback.fallbackFunction.selector, bytes1(0x00), address(1))
            )
        );
        vm.expectEmit(address(mockFallback));
        emit MockFallback.Foobar();
        uint256 res = MockFallback(address(kernel)).fallbackFunction(10);
        assertEq(res, 100);
        SelectorManager.SelectorConfig memory c = kernel.selectorConfig(MockFallback.fallbackFunction.selector);
        assertEq(address(c.target), address(mockFallback));
        assertEq(address(c.hook), address(1));
        assertTrue(c.callType == CallType.wrap(bytes1(0x00)));
        kernel.uninstallModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(MockFallback.fallbackFunction.selector))
        );
        c = kernel.selectorConfig(MockFallback.fallbackFunction.selector);
        assertEq(address(c.target), address(0));
        assertEq(address(c.hook), address(0));
        assertTrue(c.callType == CallType.wrap(bytes1(0x00)));
    }

    function test_install_selector_call_fail() external unitTest {
        kernel.installModule(
            3,
            address(mockFallback),
            abi.encode(
                hex"deadbeef", abi.encodePacked(MockFallback.fallbackFunction.selector, bytes1(0x00), address(1))
            )
        );
        vm.expectRevert(MockFallback.Limit.selector, address(mockFallback));
        MockFallback(address(kernel)).fallbackFunction(100);
    }

    function test_install_selector_delegatecall() external unitTest {
        kernel.installModule(
            3,
            address(mockFallback),
            abi.encode(
                hex"deadbeef", abi.encodePacked(MockFallback.fallbackFunction.selector, bytes1(0xff), address(1))
            )
        );
        vm.expectEmit(address(kernel));
        emit MockFallback.Foobar();
        uint256 res = MockFallback(address(kernel)).fallbackFunction(10);
        assertEq(res, 100);
    }

    function test_install_selector_delegatecall_fail() external unitTest {
        kernel.installModule(
            3,
            address(mockFallback),
            abi.encode(
                hex"deadbeef", abi.encodePacked(MockFallback.fallbackFunction.selector, bytes1(0xff), address(1))
            )
        );
        vm.expectRevert(MockFallback.Limit.selector, address(kernel));
        MockFallback(address(kernel)).fallbackFunction(100);
    }

    function test_install_selector_invalid_selector() external unitTest {
        kernel.installModule(
            3,
            address(mockFallback),
            abi.encode(
                hex"deadbeef", abi.encodePacked(MockFallback.fallbackFunction.selector, bytes1(0xff), address(1))
            )
        );
        vm.expectRevert(InvalidSelector.selector, address(kernel));
        MockFallback(address(kernel)).getData();
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

    function test_execute_fail_invalid_callType() external unitTest {
        vm.expectRevert(InvalidCallType.selector, address(kernel));
        kernel.execute(
            LibERC7579.encodeMode(bytes1(0x02), bytes1(0x01), bytes4(0), bytes22(0)),
            abi.encodePacked(address(callee), uint256(0), abi.encodeWithSelector(MockCallee.foo.selector))
        );
    }

    function test_execute_fail_invalid_execType() external unitTest {
        vm.expectRevert(InvalidExecType.selector, address(kernel));
        kernel.execute(
            LibERC7579.encodeMode(bytes1(0x00), bytes1(0x02), bytes4(0), bytes22(0)),
            abi.encodePacked(address(callee), uint256(0), abi.encodeWithSelector(MockCallee.foo.selector))
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
