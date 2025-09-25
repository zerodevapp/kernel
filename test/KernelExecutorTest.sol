pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {EntryPointLib} from "./utils/EntryPointLib.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Kernel} from "src/Kernel.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {KernelHelper} from "src/KernelHelper.sol";
import {SelectorManager} from "src/core/SelectorManager.sol";
import {KernelFactory} from "src/KernelFactory.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {KernelImmutableECDSA} from "src/KernelImmutableECDSA.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";
import {LibString} from "solady/utils/LibString.sol";
import {Install} from "src/types/Structs.sol";
import {MockFallback} from "./mock/MockFallback.sol";
import {MockExecutor} from "./mock/MockExecutor.sol";
import {MockValidator} from "./mock/MockValidator.sol";
import {MockHook} from "./mock/MockHook.sol";
import {MockPolicy} from "./mock/MockPolicy.sol";
import {MockSigner} from "./mock/MockSigner.sol";
import {MockERC721} from "./mock/MockERC721.sol";
import {MockERC1155} from "./mock/MockERC1155.sol";
import {MockCallee} from "./mock/MockCallee.sol";
import {MockKernel} from "./mock/MockKernel.sol";
import {IHook, IValidator} from "src/interfaces/IERC7579Modules.sol";
import {CallType} from "src/types/Types.sol";
import "src/types/Constants.sol";
import "forge-std/console.sol";
import "src/types/Error.sol";
import "src/types/Events.sol";
import "src/types/Structs.sol";
import {KernelTestBase} from "./KernelTestBase.sol";

abstract contract KernelExecutorTest is KernelTestBase {
    function test_install_executor_oninstall_success() external unitTest {
        assertTrue(kernel.supportsModule(2));
        address newEx = address(new MockExecutor());
        kernel.installModule(2, newEx, abi.encode(hex"deadbeef", ""));
        assertEq(address(kernel.executorConfig(newEx).hook), address(1));
        assertTrue(kernel.isModuleInstalled(2, newEx, hex""));
    }

    function test_install_executor_oninstall_fail() external unitTest {
        address newEx = makeAddr("New Executor");
        kernel.installModule(2, newEx, abi.encode(hex"", ""));
        assertEq(address(kernel.executorConfig(newEx).hook), address(1));
        assertTrue(kernel.isModuleInstalled(2, newEx, hex""));
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
        calls[0] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.foo.selector)});
        calls[1] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.lorem.selector)});
        assertEq(callee.data(), "");
        vm.expectEmit(address(callee));
        emit MockCallee.Lorem();
        kernel.executeFromExecutor(
            LibERC7579.encodeMode(bytes1(0x01), bytes1(0x00), bytes4(0), bytes22(0)), abi.encode(calls)
        );
        assertEq(callee.bar(), 1);
        assertEq(callee.data(), "lorem ipsum");
    }

    bytes32 constant MODE_EXECUTE_WITH_OP_DATA = bytes10(0x01000000000078210001);

    function encodeInstallWithExecute(Call[] memory calls, bool replayable, uint256 nonce, Install[] memory packages)
        internal
        returns (bytes memory sig)
    {
        InstallAndExecute memory ie =
            InstallAndExecute({replayable: replayable, nonce: nonce, packages: packages, signature: hex""});
        bytes32 hash = helper.installAndExecuteDigest(address(kernel), MODE_EXECUTE_WITH_OP_DATA, calls, ie);

        MockKernel mockKernel = new MockKernel(ep);

        if (!is7702) {
            vm.store(address(kernel), ERC1967_IMPLEMENTATION_SLOT, bytes32(uint256(uint160(address(mockKernel)))));
            assertEq(
                MockKernel(payable(address(kernel))).installAndExecuteDigest(MODE_EXECUTE_WITH_OP_DATA, calls, ie), hash
            );
        }
        sig = abi.encode(false, uint256(0), packages, _rootSignHash(hash, true));
    }

    function test_execute_batch_from_executor_with_install_data() external {
        address newExecutor = makeAddr("New Executor");
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 2, module: newExecutor, internalData: hex"", moduleData: hex""});

        Call[] memory calls = new Call[](2);
        calls[0] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.foo.selector)});
        calls[1] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.lorem.selector)});
        assertEq(callee.data(), "");
        vm.startPrank(newExecutor);
        bytes memory installData = encodeInstallWithExecute(calls, false, uint256(0), packages);
        vm.expectEmit(address(callee));
        emit MockCallee.Lorem();
        kernel.executeFromExecutor(MODE_EXECUTE_WITH_OP_DATA, abi.encode(calls, installData));
        assertEq(callee.bar(), 1);
        assertEq(callee.data(), "lorem ipsum");
        vm.stopPrank();
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
