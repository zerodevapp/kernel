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
        for (uint8 i = 0; i < _length; i++) {
            callees[i] = new TestCallee();
            ParamRule[] memory paramRules = new ParamRule[](2);
            paramRules[0] = ParamRule({
                offset: 0,
                condition: ParamCondition(i % 6),
                param: bytes32(uint256(100))
            });
            paramRules[1] = ParamRule({
                offset: 32,
                condition: ParamCondition((i+1) % 6),
                param: bytes32(uint256(100))
            });
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

    function _generateParam(ParamCondition condition, bool correct)  internal pure returns(uint256 param) {
        if(condition == ParamCondition.EQUAL) {
            param = correct ? 100 : 101;
        } else if(condition == ParamCondition.GREATER_THAN) {
            param = correct ? 101 : 100; 
        } else if(condition == ParamCondition.LESS_THAN) {
            param = correct ? 99 : 100;
        } else if(condition == ParamCondition.NOT_EQUAL) {
            param = correct ? 101 : 100;
        } else if(condition == ParamCondition.GREATER_THAN_OR_EQUAL) {
            param = correct ? 100 : 99;
        } else if(condition == ParamCondition.LESS_THAN_OR_EQUAL) {
            param = correct ? 100 : 101;
        }
    }

    function _buildUserOp(
        Permission[] memory permissions,
        SessionData memory sessionData,
        uint256 indexToUse,
        uint8 usingPaymasterMode,
        bool param1Faulty,
        bool param2Faulty
    ) internal view returns (UserOperation memory op) {
        op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(
                IKernel.execute.selector,
                permissions[indexToUse].target,
                0,
                abi.encodeWithSelector(
                    permissions[indexToUse].sig,
                    _generateParam(ParamCondition(indexToUse%6), !param1Faulty), // since EQ
                    _generateParam(ParamCondition((indexToUse+1)%6), !param2Faulty) // since NOT_EQ
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
    // 0, 0, 12, 0, 2, 1, 0, 1, false
    // 0, 0, 2, 0, 2, 1, 1, 7550702249 [7.55e9], false
    struct TestConfig {
        uint8 paymasterMode;
        uint8 usingPaymasterMode;
        uint8 numberOfPermissions;
        uint8 indexToUse;
        uint48 runs;
        uint48 validAfter;
        uint48 interval;
        uint48 earlyRun;
        bool faultySig;
        bool param1Faulty;
        bool param2Faulty;
    }
    function test_scenario_non_batch(
        TestConfig memory config
    ) public {
        vm.warp(1000);
        vm.assume(config.indexToUse < config.numberOfPermissions && config.numberOfPermissions > 1);
        vm.assume(config.validAfter < type(uint32).max && config.interval < type(uint32).max && config.runs < type(uint32).max);
        config.paymasterMode = config.paymasterMode % 3;
        config.usingPaymasterMode = config.usingPaymasterMode % 3;
        bool shouldFail = (config.usingPaymasterMode < config.paymasterMode) || (1000 < config.validAfter) || config.faultySig || config.param1Faulty || config.param2Faulty;
        config.runs = config.runs % 10;
        config.earlyRun = config.runs == 0 ? 0 : config.earlyRun % config.runs;
        if(config.interval == 0 || config.validAfter == 0) {
            config.earlyRun = 0;
        }
        if (config.interval > 0) {
            vm.assume(config.validAfter > 0 && config.validAfter < block.timestamp);
        } else {
            vm.assume(config.validAfter < block.timestamp);
        }
        // setup permissions
        execRule = ExecutionRule({runs: config.runs, validAfter: ValidAfter.wrap(config.validAfter), interval: config.interval});
        Permission[] memory permissions = _setup_permission(config.numberOfPermissions);
        _buildHashes(permissions);
        (uint128 lastNonce,) = sessionKeyValidator.nonces(address(kernel));
        SessionData memory sessionData = SessionData({
            merkleRoot: _getRoot(data),
            validAfter: ValidAfter.wrap(config.validAfter),
            validUntil: ValidUntil.wrap(0),
            paymaster: config.paymasterMode == 2 ? address(paymaster) : address(uint160(config.paymasterMode)),
            nonce: uint256(lastNonce) + 1//lastNonce + 1
        });
        // now encode data to op
        UserOperation memory op = _buildUserOp(permissions, sessionData, config.indexToUse, config.usingPaymasterMode, config.param1Faulty, config.param2Faulty);
        op.signature = bytes.concat(
            op.signature,
            abi.encodePacked(
                sessionKey,
                entryPoint.signUserOpHash(vm, config.faultySig ? sessionKeyPriv + 1 : sessionKeyPriv, op),
                abi.encode(permissions[config.indexToUse], _getProof(data, config.indexToUse))
            )
        );

        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        if (shouldFail) {
            vm.expectRevert();
        }
        entryPoint.handleOps(ops, beneficiary);
        if (config.interval > 0 && config.validAfter > 0 && !shouldFail) {
            (ValidAfter updatedValidAfter, uint48 r) = sessionKeyValidator.executionStatus(
                keccak256(abi.encodePacked(sessionData.nonce, uint32(config.indexToUse))), address(kernel)
            );
            assertEq(uint256(ValidAfter.unwrap(updatedValidAfter)), uint256(config.validAfter));
            if (config.runs > 0) {
                assertEq(uint256(r), uint256(1));
            } else {
                assertEq(uint256(r), uint256(0));
            }
        }
        if (!shouldFail && config.runs > 0) {
            for (uint256 i = 1; i < config.runs; i++) {
                if(config.earlyRun != i) {
                    vm.warp(config.validAfter + config.interval * i);
                } else {
                    vm.warp(config.validAfter + config.interval * i - 1);
                }
                op.nonce = op.nonce + 1;
                op.signature = _getSingleActionSignature(op, permissions, config.indexToUse);
                if (config.earlyRun == i) {
                    vm.expectRevert();
                }
                entryPoint.handleOps(ops, beneficiary);
                if (config.earlyRun == i) {
                    vm.warp(config.validAfter + config.interval * i);
                    entryPoint.handleOps(ops, beneficiary);
                }
                (ValidAfter updatedValidAfter, uint48 r) = sessionKeyValidator.executionStatus(
                    keccak256(abi.encodePacked(sessionData.nonce, uint32(config.indexToUse))), address(kernel)
                );
                if (config.validAfter > 0 && config.interval > 0) {
                    assertEq(uint256(ValidAfter.unwrap(updatedValidAfter)), uint256(config.validAfter + config.interval * i));
                }
                if(config.runs > 0) {
                    assertEq(uint256(r), uint256(i + 1));
                }
            }
            op.nonce = op.nonce + 1;
            op.signature = _getSingleActionSignature(op, permissions, config.indexToUse);
            vm.expectRevert();
            entryPoint.handleOps(ops, beneficiary);
        }
    }

    function _getSingleActionSignature(UserOperation memory _op, Permission[] memory permissions, uint8 indexToUse) internal view returns(bytes memory) {
        return abi.encodePacked(
            bytes4(0x00000001),
            abi.encodePacked(
                sessionKey,
                entryPoint.signUserOpHash(vm, sessionKeyPriv, _op),
                abi.encode(permissions[indexToUse], _getProof(data, indexToUse))
            )
        );
    }
}
