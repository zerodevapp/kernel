pragma solidity ^0.8.0;

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Kernel} from "src/Kernel.sol";
import {MockCallee} from "./mock/MockCallee.sol";
import {KernelTestBase} from "./KernelTestBase.sol";
import {PermissionId} from "src/types/Types.sol";
import {validatorToIdentifier} from "src/lib/Utils.sol";
import {SimpleAccount} from "account-abstraction/accounts/SimpleAccount.sol";
import {SimpleAccountFactory} from "account-abstraction/accounts/SimpleAccountFactory.sol";

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

    function test_userop_simple_account_compare() external entryPointTest {
        (address simpleOwner, uint256 simpleKey) = makeAddrAndKey("SimpleOwner");
        SimpleAccountFactory factory = new SimpleAccountFactory(ep);
        vm.startPrank(address(ep.senderCreator()));
        SimpleAccount account = factory.createAccount(simpleOwner, 0);
        vm.stopPrank();
        vm.deal(address(account), 1e18);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(account),
            nonce: 0,
            initCode: hex"",
            callData: abi.encodeWithSelector(
                account.execute.selector, address(callee), uint256(0), abi.encodePacked(MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        bytes32 userOpHash = ep.getUserOpHash(ops[0]);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(simpleKey, userOpHash);
        ops[0].signature = abi.encodePacked(r,s,v);
        vm.startSnapshotGas("Simple - foo()");
        ep.handleOps(ops, beneficiary);
        vm.stopSnapshotGas();
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
        assertEq(kernel.validationInfo(validatorToIdentifier(newValidator)).hook, address(1));
    }

    function test_userop_validator_hook_failed_prehook() external entryPointTest {}

    function test_userop_validator_hook_failed_posthook() external entryPointTest {}

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
            nonce: encodeNonce(false, false, false, bytes1(0x02), PermissionId.unwrap(permissionId)),
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
            nonce: encodeNonce(false, true, false, bytes1(0x02), PermissionId.unwrap(permissionId)),
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
            nonce: encodeNonce(false, true, false, bytes1(0x02), PermissionId.unwrap(permissionId)),
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
            nonce: encodeNonce(false, true, false, bytes1(0x02), PermissionId.unwrap(permissionId)),
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
            nonce: encodeNonce(false, true, false, bytes1(0x02), PermissionId.unwrap(permissionId)),
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
