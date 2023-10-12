    // SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "src/Kernel.sol";
import "src/interfaces/IKernel.sol";
import "src/validator/ECDSAValidator.sol";
import "src/factory/KernelFactory.sol";
// test artifacts
import "../mock/TestValidator.sol";
import "../mock/TestExecutor.sol";
import "../mock/TestERC721.sol";
import "../mock/TestERC20.sol";
import "../mock/TestPaymaster.sol";
// test utils
import "forge-std/Test.sol";
import "../utils/ERC4337Utils.sol";
import "../utils/Merkle.sol";
// test actions/validators
import "src/validator/SessionKeyValidator.sol";

import {KernelECDSATest} from "../KernelECDSA.t.sol";
import "../mock/TestCallee.sol";

using ERC4337Utils for IEntryPoint;

contract SessionKeyValidatorTest is KernelECDSATest {
    SessionKeyValidator sessionKeyValidator;
    TestCallee[] callees;
    ExecutionRule execRule;
    bytes32[] data;
    address sessionKey;
    uint256 sessionKeyPriv;
    TestPaymaster paymaster;
    TestPaymaster unknownPaymaster;

    function setUp() public override {
        super.setUp();
        (sessionKey, sessionKeyPriv) = makeAddrAndKey("sessionKey");
        sessionKeyValidator = new SessionKeyValidator();
        paymaster = new TestPaymaster();
        unknownPaymaster = new TestPaymaster();
        entryPoint.depositTo{value: 1e18}(address(unknownPaymaster));
        entryPoint.depositTo{value: 1e18}(address(paymaster));
    }

    function _setup_permission(uint256 _length) internal returns (Permission[] memory permissions) {
        permissions = new Permission[](_length);
        callees = new TestCallee[](_length);
        ParamRule[] memory paramRules = new ParamRule[](2);
        paramRules[0] = ParamRule({offset: 0, condition: ParamCondition.EQUAL, param: bytes32(uint256(1))});
        paramRules[1] = ParamRule({offset: 1, condition: ParamCondition.NOT_EQUAL, param: bytes32(uint256(2))});
        for (uint8 i = 0; i < _length; i++) {
            callees[i] = new TestCallee();
            permissions[i] = Permission({
                index: i,
                target: address(callees[i]),
                sig: TestCallee.addTester.selector,
                valueLimit: 0,
                rules: paramRules,
                executionRule: execRule
            });
        }
    }

    function _buildHashes(Permission[] memory permissions) internal {
        // setup permission done
        data = new bytes32[](permissions.length);
        for (uint8 i = 0; i < permissions.length; i++) {
            data[i] = keccak256(abi.encode(permissions[i]));
        }
    }

    function _buildUserOp(Permission[] memory permissions, SessionData memory sessionData, uint256 indexToUse, uint8 usingPaymasterMode) internal view returns(UserOperation memory op) {
        op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(
                IKernel.execute.selector,
                permissions[indexToUse].target,
                0,
                abi.encodeWithSelector(
                    permissions[indexToUse].sig,
                    1, // since EQ
                    1 // since NOT_EQ
                ),
                Operation.Call
            )
        );
        if (usingPaymasterMode != 0) {
            // 0 = no paymaster
            // 1 = unknown paymaster
            // 2 = correct paymaster
            op.paymasterAndData = usingPaymasterMode == 1
                ? abi.encodePacked(address(unknownPaymaster))
                : abi.encodePacked(address(paymaster));
        }
        bytes memory enableData = abi.encodePacked(
            sessionKey,
            sessionData.merkleRoot,
            sessionData.validAfter,
            sessionData.validUntil,
            sessionData.paymaster,
            sessionData.nonce
        );
        bytes32 digest = getTypedDataHash(
            IKernel.execute.selector,
            ValidAfter.unwrap(sessionData.validAfter),
            ValidUntil.unwrap(sessionData.validUntil),
            address(sessionKeyValidator),
            address(0),
            enableData
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);
        op.signature = abi.encodePacked(
            bytes4(0x00000002),
            uint48(ValidAfter.unwrap(sessionData.validAfter)),
            uint48(ValidUntil.unwrap(sessionData.validUntil)),
            address(sessionKeyValidator),
            address(0),
            uint256(enableData.length),
            enableData,
            uint256(65),
            r,
            s,
            v
        );

    }

    // scenarios to test
    // mode - 1, 2
    // paymaster - must, any, none
    // ExecRule
    // - when there is runs => when runs expired
    // - when there is validAfter => when validAfter is future
    // - when there is interval => when interval is zero, when interval is not zero
    // 21, 0, 2, 0, 0, 1, 0
    // 1, 0, 2, 0, 0, 1, 0
    function test_scenario_non_batch(
        uint8 paymasterMode,
        uint8 usingPaymasterMode,
        uint8 numberOfPermissions,
        uint8 indexToUse,
        uint48 runs,
        uint48 validAfter,
        uint48 interval
    ) public {
        vm.warp(1000);
        vm.assume(indexToUse < numberOfPermissions && numberOfPermissions > 1);
        paymasterMode = paymasterMode % 3;
        usingPaymasterMode = usingPaymasterMode % 3;
        bool shouldFail = usingPaymasterMode < paymasterMode;
        runs = runs % 3;
        if (interval > 0) {
            vm.assume(validAfter > 0 && validAfter < block.timestamp);
        } else {
            vm.assume(validAfter < block.timestamp);
        }
        // setup permissions
        execRule = ExecutionRule({runs: runs, validAfter: ValidAfter.wrap(validAfter), interval: interval});
        Permission[] memory permissions = _setup_permission(numberOfPermissions);
        _buildHashes(permissions);
        //(uint128 lastNonce,) = sessionKeyValidator.nonces(address(kernel));
        SessionData memory sessionData = SessionData({
            merkleRoot: _getRoot(data),
            validAfter: ValidAfter.wrap(validAfter),
            validUntil: ValidUntil.wrap(0),
            paymaster: paymasterMode == 2 ? address(paymaster) : address(uint160(paymasterMode)),
            nonce: 1//lastNonce + 1
        });
        // now encode data to op
        UserOperation memory op = _buildUserOp(permissions, sessionData, indexToUse, usingPaymasterMode);
        op.signature = bytes.concat(
            op.signature,
            abi.encodePacked(
                sessionKey,
                entryPoint.signUserOpHash(vm, sessionKeyPriv, op),
                abi.encode(permissions[indexToUse], _getProof(data, indexToUse))
            )
        );

        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        if (shouldFail) {
            vm.expectRevert();
        }
        entryPoint.handleOps(ops, beneficiary);
        if(!shouldFail && runs > 0) {
            for(uint256 i = 1; i <runs; i++) {
                op.nonce = op.nonce + 1;
                op.signature = bytes.concat(
                    bytes4(0x00000001),
                    abi.encodePacked(
                        sessionKey,
                        entryPoint.signUserOpHash(vm, sessionKeyPriv, op),
                        abi.encode(permissions[indexToUse], _getProof(data, indexToUse))
                    )
                );
                entryPoint.handleOps(ops, beneficiary);
            }
            op.nonce = op.nonce + 1;
            op.signature = bytes.concat(
                bytes4(0x00000001),
                abi.encodePacked(
                    sessionKey,
                    entryPoint.signUserOpHash(vm, sessionKeyPriv, op),
                    abi.encode(permissions[indexToUse], _getProof(data, indexToUse))
                )
            );
            vm.expectRevert();
            entryPoint.handleOps(ops, beneficiary);
        }

    }
}
