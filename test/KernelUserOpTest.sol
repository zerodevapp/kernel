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

abstract contract KernelUserOpTest is KernelTestBase {
    function test_executeuserop_root() external entryPointTest {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, false, false, bytes1(0), bytes20(0)),
            initCode: hex"",
            callData: abi.encodePacked(
                Kernel.executeUserOp.selector,
                abi.encodeWithSelector(
                    Kernel.execute.selector,
                    bytes32(0),
                    abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
                )
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        ops[0].signature = _rootSignUserOp(ops[0], true, false);
        vm.startPrank(address(ep));
        kernel.executeUserOp(ops[0], keccak256("hello world"));
        vm.stopPrank();
        assertEq(callee.bar(), 1);
    }

    function test_userop_root() external entryPointTest {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, false, false, bytes1(0), bytes20(0)),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector, bytes32(0), abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        ops[0].signature = _rootSignUserOp(ops[0], true, false);
        vm.startSnapshotGas("Root - foo()");
        ep.handleOps(ops, beneficiary);
        vm.stopSnapshotGas();
        assertEq(callee.bar(), 1);
    }

    function test_userop_root_replayable() external entryPointTest {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(true, false, false, bytes1(0), bytes20(0)),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector, bytes32(0), abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        ops[0].signature = _rootSignUserOp(ops[0], true, true);
        ep.handleOps(ops, beneficiary);
        assertEq(callee.bar(), 1);
    }

    function test_userop_root_aa24_validation_failed() external entryPointTest {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, false, false, bytes1(0x00), bytes20(0)),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector, bytes32(0), abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        ops[0].signature = _rootSignUserOp(ops[0], false, false);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        ep.handleOps(ops, beneficiary);
    }

    function test_userop_validator_aa24_notinstalled() external entryPointTest {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, false, false, bytes1(0x01), bytes20(address(newValidator))),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector, bytes32(0), abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        ops[0].signature = _validatorSignUserOp(ops[0], true, false);
        vm.expectRevert();
        ep.handleOps(ops, beneficiary);
    }

    function test_userop_validator_enable() external entryPointTest {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, true, false, bytes1(0x01), bytes20(address(newValidator))),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector, bytes32(0), abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        ops[0].signature = encodeEnableValidatorSignature(
            Kernel.execute.selector, 0, true, false, _rootSignHash, _validatorSignUserOp(ops[0], true, false)
        );
        ep.handleOps(ops, beneficiary);
        assertEq(callee.bar(), 1);
    }

    function test_userop_validator_aa24_enable_fail_wrong_signature() external entryPointTest {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, true, false, bytes1(0x01), bytes20(address(newValidator))),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector, bytes32(0), abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        ops[0].signature = encodeEnableValidatorSignature(
            Kernel.execute.selector, 0, false, false, _rootSignHash, _validatorSignUserOp(ops[0], true, false)
        );
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        ep.handleOps(ops, beneficiary);
    }

    function test_userop_validator_aa24_validation_failed() external entryPointTest {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, true, false, bytes1(0x01), bytes20(address(newValidator))),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector, bytes32(0), abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });

        ops[0].signature = encodeEnableValidatorSignature(
            Kernel.execute.selector, 0, true, false, _rootSignHash, _validatorSignUserOp(ops[0], false, false)
        );
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        ep.handleOps(ops, beneficiary);
    }

    function test_userop_permission_aa24_notinstalled() external entryPointTest {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, false, false, bytes1(0x02), permissionId),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector, bytes32(0), abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        ops[0].signature = _permissionSignUserOp(ops[0], true, false);
        //vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        vm.expectRevert();
        ep.handleOps(ops, beneficiary);
    }

    function test_userop_permission_enable() external entryPointTest {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, true, false, bytes1(0x02), permissionId),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector, bytes32(0), abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });

        ops[0].signature = encodeEnablePermissionSignature(
            Kernel.execute.selector, 0, true, false, _rootSignHash, _permissionSignUserOp(ops[0], true, false)
        );
        ep.handleOps(ops, beneficiary);
        assertEq(callee.bar(), 1);
    }

    function test_userop_permission_aa24_enable_fail_wrong_signature() external entryPointTest {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, true, false, bytes1(0x02), permissionId),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector, bytes32(0), abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        ops[0].signature = encodeEnablePermissionSignature(
            Kernel.execute.selector, 0, false, false, _rootSignHash, _permissionSignUserOp(ops[0], true, false)
        );
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        ep.handleOps(ops, beneficiary);
    }

    function test_userop_permission_aa24_policy_failed() external entryPointTest {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, true, false, bytes1(0x02), permissionId),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector, bytes32(0), abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        ops[0].signature = encodeEnablePermissionSignature(
            Kernel.execute.selector, 0, true, false, _rootSignHash, _permissionSignUserOp(ops[0], false, false)
        );
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        ep.handleOps(ops, beneficiary);
    }

    function test_userop_permission_aa24_signer_validation_failed() external entryPointTest {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, true, false, bytes1(0x02), permissionId),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector, bytes32(0), abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        permissionRevertIndex = 1;
        ops[0].signature = encodeEnablePermissionSignature(
            Kernel.execute.selector, 0, true, false, _rootSignHash, _permissionSignUserOp(ops[0], false, false)
        );
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        ep.handleOps(ops, beneficiary);
    }
}
