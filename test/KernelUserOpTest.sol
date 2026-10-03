pragma solidity ^0.8.0;

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Kernel} from "src/Kernel.sol";
import {MockCallee} from "./mock/MockCallee.sol";
import {KernelTestBase} from "./KernelTestBase.sol";
import {PermissionId} from "src/types/Types.sol";
import {ValidationId} from "src/types/Types.sol";
import {InvalidVid, UnauthorizedCallData} from "src/types/Error.sol";
import {permissionToIdentifier, validatorToIdentifier} from "src/lib/Utils.sol";
import {SimpleAccount} from "account-abstraction/accounts/SimpleAccount.sol";
import {SimpleAccountFactory} from "account-abstraction/accounts/SimpleAccountFactory.sol";
import {LibBytes} from "solady/utils/LibBytes.sol";

abstract contract KernelUserOpTest is KernelTestBase {
    error Result(uint256 gas);

    function _rootUserOpWithCallData(bytes memory callData) internal view returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, false, false, bytes1(0), bytes20(0)),
            initCode: hex"",
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
    }

    function test_validateuserop_rejects_direct_validateuserop_calldata() external entryPointTest {
        PackedUserOperation memory op = _rootUserOpWithCallData(abi.encodePacked(Kernel.validateUserOp.selector));

        vm.startPrank(address(ep));
        vm.expectRevert(UnauthorizedCallData.selector);
        kernel.validateUserOp(op, bytes32(0), 0);
        vm.stopPrank();
    }

    function test_validateuserop_rejects_wrapped_validateuserop_calldata() external entryPointTest {
        PackedUserOperation memory op =
            _rootUserOpWithCallData(abi.encodePacked(Kernel.executeUserOp.selector, Kernel.validateUserOp.selector));

        vm.startPrank(address(ep));
        vm.expectRevert(UnauthorizedCallData.selector);
        kernel.validateUserOp(op, bytes32(0), 0);
        vm.stopPrank();
    }

    function estimateUserOpGasLimit(PackedUserOperation memory op) internal returns (uint128, uint128) {
        try this.simulateEntrypointCall(op) {}
        catch (bytes memory err) {
            bytes32 data = LibBytes.load(err, 4);
            // forge-lint: disable-next-line(unsafe-typecast)
            return (uint128(bytes16(data)), uint128(uint256(data)));
        }
        return (0, 0);
    }

    function simulateEntrypointCall(PackedUserOperation calldata op) external {
        bytes32 hash = ep.getUserOpHash(op);
        vm.startPrank(address(ep));
        uint256 gas = gasleft();
        Kernel(payable(op.sender)).validateUserOp(op, hash, 1);
        gas = gas - gasleft();
        vm.stopPrank();
        // forge-lint: disable-next-line(unsafe-typecast)
        uint128 vgl = uint128(gas) + 30000;
        vm.startPrank(address(ep));
        gas = gasleft();
        (bool success,) = op.sender.call(op.callData);
        gas = gas - gasleft();
        require(success, "Call Failed");
        vm.stopPrank();
        // forge-lint: disable-next-line(unsafe-typecast)
        uint128 egl = uint128(gas) + 30000;
        revert Result(uint256(bytes32(abi.encodePacked(uint128(vgl), uint128(egl)))));
    }

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
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        (uint128 vgl, uint128 egl) = estimateUserOpGasLimit(ops[0]);
        ops[0].accountGasLimits = bytes32(abi.encodePacked(uint128(vgl), uint128(egl)));
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
            accountGasLimits: bytes32(abi.encodePacked(uint128(100000), uint128(100000))),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        bytes32 userOpHash = ep.getUserOpHash(ops[0]);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(simpleKey, userOpHash);
        ops[0].signature = abi.encodePacked(r, s, v);
        (uint128 vgl, uint128 egl) = estimateUserOpGasLimit(ops[0]);
        ops[0].accountGasLimits = bytes32(abi.encodePacked(uint128(vgl), uint128(egl)));
        userOpHash = ep.getUserOpHash(ops[0]);
        (v, r, s) = vm.sign(simpleKey, userOpHash);
        ops[0].signature = abi.encodePacked(r, s, v);
        uint256 bal = ep.balanceOf(address(account)) + address(account).balance;
        vm.startPrank(beneficiary, beneficiary);
        ep.handleOps(ops, beneficiary);
        vm.stopPrank();
        uint256 used = bal - (ep.balanceOf(address(account)) + address(account).balance);
        vm.snapshotValue("Simple - foo()", used);
        assertEq(callee.bar(), 1);
    }

    function test_userop_root() external entryPointTest {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, false, false, bytes1(0), bytes20(0)),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector,
                bytes32(0),
                abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 0,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        ops[0].signature = _rootSignUserOp(ops[0], true, false);
        (uint128 vgl, uint128 egl) = estimateUserOpGasLimit(ops[0]);
        ops[0].accountGasLimits = bytes32(abi.encodePacked(uint128(vgl), uint128(egl)));
        ops[0].signature = _rootSignUserOp(ops[0], true, false);
        uint256 bal = ep.balanceOf(address(kernel)) + address(kernel).balance;
        vm.startPrank(beneficiary, beneficiary);
        ep.handleOps(ops, beneficiary);
        vm.stopPrank();
        uint256 used = bal - (ep.balanceOf(address(kernel)) + address(kernel).balance);
        vm.snapshotValue("Root - foo()", used);
        assertEq(callee.bar(), 1);
    }

    function test_userop_root_replayable() external entryPointTest {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(true, false, false, bytes1(0), bytes20(0)),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector,
                bytes32(0),
                abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        ops[0].signature = _rootSignUserOp(ops[0], true, true);
        vm.startPrank(beneficiary, beneficiary);
        ep.handleOps(ops, beneficiary);
        vm.stopPrank();
        assertEq(callee.bar(), 1);
    }

    function test_userop_root_aa24_validation_failed() external entryPointTest {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, false, false, bytes1(0x00), bytes20(0)),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector,
                bytes32(0),
                abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        ops[0].signature = _rootSignUserOp(ops[0], false, false);
        vm.startPrank(beneficiary, beneficiary);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        ep.handleOps(ops, beneficiary);
        vm.stopPrank();
    }

    function test_userop_validator_aa24_notinstalled() external entryPointTest {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, false, false, bytes1(0x01), bytes20(address(newValidator))),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector,
                bytes32(0),
                abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        ops[0].signature = _validatorSignUserOp(ops[0], true, false);
        vm.startPrank(beneficiary, beneficiary);
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSelector(InvalidVid.selector, validatorToIdentifier(newValidator))
            )
        );
        ep.handleOps(ops, beneficiary);
        vm.stopPrank();
    }

    function test_userop_validator_enable() external entryPointTest {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, true, false, bytes1(0x01), bytes20(address(newValidator))),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector,
                bytes32(0),
                abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
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
        vm.startPrank(beneficiary, beneficiary);
        ep.handleOps(ops, beneficiary);
        vm.stopPrank();
        assertEq(callee.bar(), 1);
        assertTrue(kernel.validationInfo(validatorToIdentifier(newValidator)).installed);
    }

    function test_userop_validator_aa24_enable_fail_wrong_signature() external entryPointTest {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, true, false, bytes1(0x01), bytes20(address(newValidator))),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector,
                bytes32(0),
                abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
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
        vm.startPrank(beneficiary, beneficiary);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        ep.handleOps(ops, beneficiary);
        vm.stopPrank();
    }

    // Regression (audit H-01): enable-mode install must NOT persist when the root signature
    // fails, even when validateUserOp is invoked outside the EntryPoint validation phase (during
    // execution EntryPoint calls the account with arbitrary calldata and ignores the returned
    // validationData). Before the fix, _processUserOp installed the package and advanced the
    // nonce before the failed validationData was ever checked, so a scoped key could install
    // arbitrary modules without root approval.
    function test_userop_enable_failed_root_sig_does_not_install() external entryPointTest {
        // newValidator is not installed yet.
        assertFalse(kernel.validationInfo(validatorToIdentifier(newValidator)).installed);

        PackedUserOperation memory op = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, true, false, bytes1(0x01), bytes20(address(newValidator))),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector,
                bytes32(0),
                abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        // enableSuccess = false -> the root signature over the install digest is invalid.
        op.signature = encodeEnableValidatorSignature(
            Kernel.execute.selector, 0, false, false, _rootSignHash, _validatorSignUserOp(op, true, false)
        );

        // Simulate the execution-phase re-entry: EntryPoint calls validateUserOp and discards
        // the return value.
        vm.prank(address(ep));
        uint256 validationData = kernel.validateUserOp(op, bytes32(0), 0);

        // Failed root signature must surface as validation failure...
        assertEq(uint160(validationData), 1, "H-01: failed root sig must return SIG_VALIDATION_FAILED");
        // ...and the module must NOT have been installed.
        assertFalse(
            kernel.validationInfo(validatorToIdentifier(newValidator)).installed,
            "H-01: module installed despite failed root signature"
        );
    }

    function test_userop_validator_aa24_validation_failed() external entryPointTest {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, true, false, bytes1(0x01), bytes20(address(newValidator))),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector,
                bytes32(0),
                abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
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
        vm.startPrank(beneficiary, beneficiary);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        ep.handleOps(ops, beneficiary);
        vm.stopPrank();
    }

    function test_userop_permission_aa24_notinstalled() external entryPointTest {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, false, false, bytes1(0x02), PermissionId.unwrap(permissionId)),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector,
                bytes32(0),
                abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        ops[0].signature = _permissionSignUserOp(ops[0], true, false);
        //vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        vm.startPrank(beneficiary, beneficiary);
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSelector(InvalidVid.selector, permissionToIdentifier(permissionId))
            )
        );
        ep.handleOps(ops, beneficiary);
        vm.stopPrank();
    }

    function test_userop_permission_enable() external entryPointTest {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, true, false, bytes1(0x02), PermissionId.unwrap(permissionId)),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector,
                bytes32(0),
                abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
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
        vm.startPrank(beneficiary, beneficiary);
        ep.handleOps(ops, beneficiary);
        vm.stopPrank();
        assertEq(callee.bar(), 1);
    }

    function test_userop_permission_aa24_enable_fail_wrong_signature() external entryPointTest {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, true, false, bytes1(0x02), PermissionId.unwrap(permissionId)),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector,
                bytes32(0),
                abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
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
        vm.startPrank(beneficiary, beneficiary);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        ep.handleOps(ops, beneficiary);
        vm.stopPrank();
    }

    function test_userop_permission_aa24_policy_failed() external entryPointTest {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, true, false, bytes1(0x02), PermissionId.unwrap(permissionId)),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector,
                bytes32(0),
                abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
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
        vm.startPrank(beneficiary, beneficiary);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        ep.handleOps(ops, beneficiary);
        vm.stopPrank();
    }

    function test_userop_permission_aa24_signer_validation_failed() external entryPointTest {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, true, false, bytes1(0x02), PermissionId.unwrap(permissionId)),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector,
                bytes32(0),
                abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
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
        vm.startPrank(beneficiary, beneficiary);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        ep.handleOps(ops, beneficiary);
        vm.stopPrank();
    }

    function test_userop_invalid_type() external entryPointTest {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, false, false, bytes1(0x03), bytes20(0)),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector,
                bytes32(0),
                abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        ops[0].signature = _rootSignUserOp(ops[0], true, false);
        vm.startPrank(beneficiary, beneficiary);
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSelector(
                    InvalidVid.selector, ValidationId.wrap(bytes21(abi.encodePacked(bytes1(0x03), bytes20(0))))
                )
            )
        );
        ep.handleOps(ops, beneficiary);
        vm.stopPrank();
    }
}
