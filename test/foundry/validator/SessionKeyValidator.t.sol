// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "src/Kernel.sol";
import "src/interfaces/IKernel.sol";
import "src/validator/ECDSAValidator.sol";
import "src/factory/KernelFactory.sol";
import {Call} from "src/common/Structs.sol";
// test artifacts
import "src/mock/TestValidator.sol";
import "src/mock/TestExecutor.sol";
import "src/mock/TestERC721.sol";
import "src/mock/TestERC20.sol";
import "src/mock/TestPaymaster.sol";
// test utils
import "forge-std/Test.sol";
import "src/utils/ERC4337Utils.sol";
import "../utils/Merkle.sol";
// test actions/validators
import "src/validator/SessionKeyValidator.sol";

import {KernelECDSATest} from "../KernelECDSA.t.sol";
import "src/mock/TestCallee.sol";
import "src/mock/TestERC20.sol";

using ERC4337Utils for IEntryPoint;

contract SessionKeyValidatorTest is KernelECDSATest {
    SessionKeyValidator sessionKeyValidator;
    TestCallee[] callees;
    TestERC20[] erc20s;
    ExecutionRule execRule;
    bytes32[] data;
    address sessionKey;
    uint256 sessionKeyPriv;
    TestPaymaster paymaster;
    TestPaymaster unknownPaymaster;
    address recipient;

    function setUp() public override {
        super.setUp();
        (sessionKey, sessionKeyPriv) = makeAddrAndKey("sessionKey");
        sessionKeyValidator = new SessionKeyValidator();
        paymaster = new TestPaymaster();
        unknownPaymaster = new TestPaymaster();
        entryPoint.depositTo{value: 1e18}(address(unknownPaymaster));
        entryPoint.depositTo{value: 1e18}(address(paymaster));
        recipient = makeAddr("recipient");
    }

    function _setup_permission(uint256 _length, bool isDelegateCall)
        internal
        returns (Permission[] memory permissions)
    {
        permissions = new Permission[](_length);
        callees = new TestCallee[](_length);
        if (isDelegateCall) {
            erc20s = new TestERC20[](_length);
        }
        for (uint8 i = 0; i < _length; i++) {
            address target;
            bytes4 sig;
            if (isDelegateCall) {
                erc20s[i] = new TestERC20();
                target = address(callees[i]);
                sig = TestCallee.transferErc20Tester.selector;
                erc20s[i].mint(address(kernel), 200);
            } else {
                callees[i] = new TestCallee();
                target = address(callees[i]);
                sig = TestCallee.addTester.selector;
            }
            ParamRule[] memory paramRules = new ParamRule[](2);
            if (isDelegateCall) {
                paramRules[0] =
                    ParamRule({offset: 0, condition: ParamCondition(0), param: bytes32(uint256(uint160(recipient)))});
            } else {
                paramRules[0] = ParamRule({offset: 0, condition: ParamCondition(i % 6), param: bytes32(uint256(100))});
            }
            paramRules[1] =
                ParamRule({offset: 32, condition: ParamCondition((i + 1) % 6), param: bytes32(uint256(100))});
            permissions[i] = Permission({
                index: i,
                target: target,
                sig: sig,
                valueLimit: 0,
                rules: paramRules,
                executionRule: execRule,
                operation: isDelegateCall ? Operation.DelegateCall : Operation.Call
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

    function _generateParam(ParamCondition condition, bool correct) internal pure returns (uint256 param) {
        if (condition == ParamCondition.EQUAL) {
            param = correct ? 100 : 101;
        } else if (condition == ParamCondition.GREATER_THAN) {
            param = correct ? 101 : 100;
        } else if (condition == ParamCondition.LESS_THAN) {
            param = correct ? 99 : 100;
        } else if (condition == ParamCondition.NOT_EQUAL) {
            param = correct ? 101 : 100;
        } else if (condition == ParamCondition.GREATER_THAN_OR_EQUAL) {
            param = correct ? 100 : 99;
        } else if (condition == ParamCondition.LESS_THAN_OR_EQUAL) {
            param = correct ? 100 : 101;
        }
    }

    function _buildUserOpBatch(
        Permission[] memory permissions,
        SessionData memory sessionData,
        uint256 indexToUse,
        uint8 usingPaymasterMode,
        bool param1Faulty,
        bool param2Faulty
    ) internal view returns (UserOperation memory op) {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            to: permissions[indexToUse].target,
            value: 0,
            data: abi.encodeWithSelector(
                permissions[indexToUse].sig,
                _generateParam(ParamCondition(indexToUse % 6), !param1Faulty),
                _generateParam(ParamCondition((indexToUse + 1) % 6), !param2Faulty)
                )
        });

        op = buildUserOperation(abi.encodeWithSelector(IKernel.executeBatch.selector, calls));
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
            IKernel.executeBatch.selector,
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

    function _buildUserOp(
        Permission[] memory permissions,
        SessionData memory sessionData,
        uint256 indexToUse,
        uint8 usingPaymasterMode,
        bool param1Faulty,
        bool param2Faulty,
        bool isDelegateCall
    ) internal view returns (UserOperation memory op) {
        bytes4 selector = isDelegateCall ? IKernel.executeDelegateCall.selector : IKernel.execute.selector;
        op = buildUserOperation(
            isDelegateCall
                ? abi.encodeWithSelector(
                    selector,
                    permissions[indexToUse].target,
                    abi.encodeWithSelector(
                        permissions[indexToUse].sig,
                        recipient,
                        _generateParam(ParamCondition((indexToUse + 1) % 6), !param2Faulty) // since NOT_EQ
                    )
                )
                : abi.encodeWithSelector(
                    selector,
                    permissions[indexToUse].target,
                    0,
                    abi.encodeWithSelector(
                        permissions[indexToUse].sig,
                        _generateParam(ParamCondition(indexToUse % 6), !param1Faulty), // since EQ
                        _generateParam(ParamCondition((indexToUse + 1) % 6), !param2Faulty) // since NOT_EQ
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
            selector,
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
        bool wrongProof;
        bool isDelegateCall;
    }

    struct BatchTestConfig {
        uint8 count;
    }

    function test_scenario_batch(TestConfig memory config, BatchTestConfig memory batchConfig) public {
        vm.warp(1000);
        if (batchConfig.count == 0) {
            batchConfig.count = 1;
        }
        config.runs = 0;
        config.interval = 0;
        config.validAfter = 0; // TODO: runs not checked with batch
        vm.assume(!config.isDelegateCall);
        vm.assume(config.indexToUse < config.numberOfPermissions && config.numberOfPermissions > 1);
        vm.assume(
            config.validAfter < type(uint32).max && config.interval < type(uint32).max && config.runs < type(uint32).max
        );
        config.paymasterMode = config.paymasterMode % 3;
        config.usingPaymasterMode = config.usingPaymasterMode % 3;
        bool shouldFail = (config.usingPaymasterMode < config.paymasterMode) || (1000 < config.validAfter)
            || config.faultySig || config.param1Faulty || config.param2Faulty || config.wrongProof;
        config.runs = config.runs % 10;
        config.earlyRun = config.runs == 0 ? 0 : config.earlyRun % config.runs;
        if (config.interval == 0 || config.validAfter == 0) {
            config.earlyRun = 0;
        }
        if (config.interval > 0) {
            vm.assume(config.validAfter > 0 && config.validAfter < block.timestamp);
        } else {
            vm.assume(config.validAfter < block.timestamp);
        }
        // setup permissions
        execRule = ExecutionRule({
            runs: config.runs,
            validAfter: ValidAfter.wrap(config.validAfter),
            interval: config.interval
        });
        Permission[] memory permissions = _setup_permission(config.numberOfPermissions, false);
        _buildHashes(permissions);
        (uint128 lastNonce,) = sessionKeyValidator.nonces(address(kernel));
        SessionData memory sessionData = SessionData({
            merkleRoot: _getRoot(data),
            validAfter: ValidAfter.wrap(config.validAfter),
            validUntil: ValidUntil.wrap(0),
            paymaster: config.paymasterMode == 2 ? address(paymaster) : address(uint160(config.paymasterMode)),
            nonce: uint256(lastNonce) + 1 //lastNonce + 1
        });
        // now encode data to op
        UserOperation memory op = _buildUserOpBatch(
            permissions,
            sessionData,
            config.indexToUse,
            config.usingPaymasterMode,
            config.param1Faulty,
            config.param2Faulty
        );
        bytes32[][] memory proofs = new bytes32[][](batchConfig.count);
        Permission[] memory usingPermission = new Permission[](batchConfig.count);
        for (uint256 i = 0; i < batchConfig.count; i++) {
            proofs[i] = _getProof(data, config.indexToUse, config.wrongProof);
            usingPermission[i] = permissions[config.indexToUse];
        }
        op.signature = bytes.concat(
            op.signature,
            abi.encodePacked(
                sessionKey,
                entryPoint.signUserOpHash(vm, config.faultySig ? sessionKeyPriv + 1 : sessionKeyPriv, op),
                abi.encode(usingPermission, proofs)
            )
        );

        if (shouldFail) {
            vm.expectRevert();
        }
        performUserOperation(op);
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
                if (config.earlyRun != i) {
                    vm.warp(config.validAfter + config.interval * i);
                } else {
                    vm.warp(config.validAfter + config.interval * i - 1);
                }
                op.nonce = op.nonce + 1;
                op.signature = _getBatchActionSignature(op, permissions, config.indexToUse);
                if (config.earlyRun == i) {
                    vm.expectRevert();
                }
                performUserOperation(op);
                if (config.earlyRun == i) {
                    vm.warp(config.validAfter + config.interval * i);
                    performUserOperation(op);
                }
                (ValidAfter updatedValidAfter, uint48 r) = sessionKeyValidator.executionStatus(
                    keccak256(abi.encodePacked(sessionData.nonce, uint32(config.indexToUse))), address(kernel)
                );
                if (config.validAfter > 0 && config.interval > 0) {
                    assertEq(
                        uint256(ValidAfter.unwrap(updatedValidAfter)), uint256(config.validAfter + config.interval * i)
                    );
                }
                if (config.runs > 0) {
                    assertEq(uint256(r), uint256(i + 1));
                }
            }
            op.nonce = op.nonce + 1;
            op.signature = _getBatchActionSignature(op, permissions, config.indexToUse);
            vm.expectRevert();
            performUserOperation(op);
        }
    }

    function test_scenario_non_batch(TestConfig memory config) public {
        vm.warp(1000);
        vm.assume(config.indexToUse < config.numberOfPermissions && config.numberOfPermissions > 1);
        vm.assume(
            config.validAfter < type(uint32).max && config.interval < type(uint32).max && config.runs < type(uint32).max
        );
        config.paymasterMode = config.paymasterMode % 3;
        config.usingPaymasterMode = config.usingPaymasterMode % 3;
        bool shouldFail = (config.usingPaymasterMode < config.paymasterMode) || (1000 < config.validAfter)
            || config.faultySig || (config.param1Faulty && !config.isDelegateCall) || config.param2Faulty
            || config.wrongProof;
        config.runs = config.runs % 10;
        config.earlyRun = config.runs == 0 ? 0 : config.earlyRun % config.runs;
        if (config.interval == 0 || config.validAfter == 0) {
            config.earlyRun = 0;
        }
        if (config.interval > 0) {
            vm.assume(config.validAfter > 0 && config.validAfter < block.timestamp);
        } else {
            vm.assume(config.validAfter < block.timestamp);
        }
        // setup permissions
        execRule = ExecutionRule({
            runs: config.runs,
            validAfter: ValidAfter.wrap(config.validAfter),
            interval: config.interval
        });
        Permission[] memory permissions = _setup_permission(config.numberOfPermissions, config.isDelegateCall);
        _buildHashes(permissions);
        (uint128 lastNonce,) = sessionKeyValidator.nonces(address(kernel));
        SessionData memory sessionData = SessionData({
            merkleRoot: _getRoot(data),
            validAfter: ValidAfter.wrap(config.validAfter),
            validUntil: ValidUntil.wrap(0),
            paymaster: config.paymasterMode == 2 ? address(paymaster) : address(uint160(config.paymasterMode)),
            nonce: uint256(lastNonce) + 1 //lastNonce + 1
        });
        // now encode data to op
        UserOperation memory op = _buildUserOp(
            permissions,
            sessionData,
            config.indexToUse,
            config.usingPaymasterMode,
            config.param1Faulty,
            config.param2Faulty,
            config.isDelegateCall
        );
        op.signature = bytes.concat(
            op.signature,
            abi.encodePacked(
                sessionKey,
                entryPoint.signUserOpHash(vm, config.faultySig ? sessionKeyPriv + 1 : sessionKeyPriv, op),
                abi.encode(permissions[config.indexToUse], _getProof(data, config.indexToUse, config.wrongProof))
            )
        );

        if (shouldFail) {
            vm.expectRevert();
        }
        performUserOperation(op);
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
                if (config.earlyRun != i) {
                    vm.warp(config.validAfter + config.interval * i);
                } else {
                    vm.warp(config.validAfter + config.interval * i - 1);
                }
                op.nonce = op.nonce + 1;
                op.signature = _getSingleActionSignature(op, permissions, config.indexToUse);
                if (config.earlyRun == i) {
                    vm.expectRevert();
                }
                performUserOperation(op);
                if (config.earlyRun == i) {
                    vm.warp(config.validAfter + config.interval * i);
                    performUserOperation(op);
                }
                (ValidAfter updatedValidAfter, uint48 r) = sessionKeyValidator.executionStatus(
                    keccak256(abi.encodePacked(sessionData.nonce, uint32(config.indexToUse))), address(kernel)
                );
                if (config.validAfter > 0 && config.interval > 0) {
                    assertEq(
                        uint256(ValidAfter.unwrap(updatedValidAfter)), uint256(config.validAfter + config.interval * i)
                    );
                }
                if (config.runs > 0) {
                    assertEq(uint256(r), uint256(i + 1));
                }
            }
            op.nonce = op.nonce + 1;
            op.signature = _getSingleActionSignature(op, permissions, config.indexToUse);
            vm.expectRevert();
            performUserOperation(op);
        }
    }

    function _getBatchActionSignature(UserOperation memory _op, Permission[] memory permissions, uint8 indexToUse)
        internal
        view
        returns (bytes memory)
    {
        Permission[] memory _permissions = new Permission[](1);
        _permissions[0] = permissions[indexToUse];
        bytes32[][] memory _proofs = new bytes32[][](1);
        _proofs[0] = _getProof(data, indexToUse, false);
        return abi.encodePacked(
            bytes4(0x00000001),
            abi.encodePacked(
                sessionKey, entryPoint.signUserOpHash(vm, sessionKeyPriv, _op), abi.encode(_permissions, _proofs)
            )
        );
    }

    function _getSingleActionSignature(UserOperation memory _op, Permission[] memory permissions, uint8 indexToUse)
        internal
        view
        returns (bytes memory)
    {
        return abi.encodePacked(
            bytes4(0x00000001),
            abi.encodePacked(
                sessionKey,
                entryPoint.signUserOpHash(vm, sessionKeyPriv, _op),
                abi.encode(permissions[indexToUse], _getProof(data, indexToUse, false))
            )
        );
    }
}
