// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "src/Kernel.sol";
import "src/validator/ECDSAValidator.sol";
import "src/factory/KernelFactory.sol";
// test artifacts
import "src/test/TestValidator.sol";
import "src/test/TestExecutor.sol";
import "src/test/TestERC721.sol";
import "src/test/TestERC20.sol";
// test utils
import "forge-std/Test.sol";
import "../utils/ERC4337Utils.sol";
// test actions/validators
import "src/validator/SessionKeyValidator.sol";

import {KernelECDSATest} from "../KernelECDSA.t.sol";

using ERC4337Utils for EntryPoint;

contract SessionKeyValidatorTest is KernelECDSATest {
    ExecuteSessionKeyValidator sessionKeyValidator;
    TestERC20 testToken;
    TestERC20 testToken2;
    address sessionKey;
    uint256 sessionKeyPriv;

    function setUp() public override {
        super.setUp();
        (sessionKey, sessionKeyPriv) = makeAddrAndKey("sessionKey");
        testToken = new TestERC20();
        testToken2 = new TestERC20();
        sessionKeyValidator = new ExecuteSessionKeyValidator();
    }

    function test_mode_2_no_paymaster() external {
        testToken.mint(address(kernel), 100e18);
        UserOperation memory op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(
                Kernel.execute.selector,
                address(testToken),
                0,
                abi.encodeWithSelector(ERC20.transfer.selector, beneficiary, 100),
                Operation.Call
            )
        );

        ParamRule[] memory rules = new ParamRule[](1);
        ExecutionRule memory execRule = ExecutionRule({validAfter: ValidAfter.wrap(0), interval: 0, runs: 0});
        rules[0] = ParamRule({offset: 32, condition: ParamCondition.LESS_THAN_OR_EQUAL, param: bytes32(uint256(1e18))});

        bytes32[] memory data = new bytes32[](2);
        data[0] = keccak256(
            abi.encode(
                Permission({
                    index: 0,
                    valueLimit: 0,
                    target: address(testToken),
                    sig: ERC20.transfer.selector,
                    rules: rules,
                    executionRule: execRule
                })
            )
        );

        data[1] = keccak256(
            abi.encode(
                Permission({
                    index: 1,
                    valueLimit: 0,
                    target: address(testToken2),
                    sig: ERC20.transfer.selector,
                    executionRule: execRule,
                    rules: rules
                })
            )
        );

        bytes32 merkleRoot = _getRoot(data);
        bytes memory enableData = abi.encodePacked(sessionKey, merkleRoot, uint48(0), uint48(0), address(0));
        bytes32 digest = getTypedDataHash(
            address(kernel), Kernel.execute.selector, 0, 0, address(sessionKeyValidator), address(0), enableData
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);

        op.signature = abi.encodePacked(
            bytes4(0x00000002),
            uint48(0),
            uint48(0),
            address(sessionKeyValidator),
            address(0),
            uint256(enableData.length),
            enableData,
            uint256(65),
            r,
            s,
            v
        );
        op.signature = bytes.concat(
            op.signature,
            abi.encodePacked(
                sessionKey,
                entryPoint.signUserOpHash(vm, sessionKeyPriv, op),
                abi.encode(
                    Permission({
                        index: 0,
                        valueLimit: 0,
                        target: address(testToken),
                        sig: ERC20.transfer.selector,
                        executionRule: execRule,
                        rules: rules
                    }),
                    _getProof(data, 0)
                )
            )
        );
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        logGas(op);

        entryPoint.handleOps(ops, beneficiary);
    }

    function pack_multi_calls() internal view returns (UserOperation memory op) {
        Call[] memory calls = new Call[](2);
        calls[0] = Call({
            to: address(testToken),
            value: 0,
            data: abi.encodeWithSelector(ERC20.transfer.selector, beneficiary, 100)
        });
        calls[1] = Call({
            to: address(testToken2),
            value: 0,
            data: abi.encodeWithSelector(ERC20.transfer.selector, beneficiary, 100)
        });
        op = entryPoint.fillUserOp(address(kernel), abi.encodeWithSelector(Kernel.executeBatch.selector, calls));
    }

    function generate_merkle_root(ParamRule[] memory rules, ExecutionRule memory execRule)
        internal
        view
        returns (bytes32)
    {
        bytes32[] memory data = new bytes32[](2);
        data[0] = keccak256(
            abi.encode(
                Permission({
                    index: 0,
                    valueLimit: 0,
                    target: address(testToken),
                    sig: ERC20.transfer.selector,
                    rules: rules,
                    executionRule: execRule
                })
            )
        );

        data[1] = keccak256(
            abi.encode(
                Permission({
                    index: 1,
                    valueLimit: 0,
                    target: address(testToken2),
                    sig: ERC20.transfer.selector,
                    executionRule: execRule,
                    rules: rules
                })
            )
        );

        return _getRoot(data);
    }

    function generate_proofs(ParamRule[] memory rules, ExecutionRule memory execRule)
        internal
        view
        returns (bytes memory)
    {
        bytes32[] memory proof;
        Permission[] memory permissions = new Permission[](2);
        permissions[0] = Permission({
            index: 0,
            valueLimit: 0,
            target: address(testToken),
            sig: ERC20.transfer.selector,
            executionRule: execRule,
            rules: rules
        });
        permissions[1] = Permission({
            index: 1,
            valueLimit: 0,
            target: address(testToken2),
            sig: ERC20.transfer.selector,
            executionRule: execRule,
            rules: rules
        });
        // since we use all of them, flags[0] == true
        bool[] memory flags = new bool[](1);
        flags[0] = true;
        uint256[] memory indexes = new uint256[](2);
        indexes[0] = 0;
        indexes[1] = 1;

        return abi.encode(
            permissions,
            proof, //data
            flags,
            indexes
        );
    }

    function test_mode_2_no_paymaster_multiple() external {
        testToken.mint(address(kernel), 100e18);
        UserOperation memory op = pack_multi_calls();
        ParamRule[] memory rules = new ParamRule[](1);
        ExecutionRule memory execRule = ExecutionRule({validAfter: ValidAfter.wrap(0), interval: 0, runs: 0});
        rules[0] = ParamRule({offset: 32, condition: ParamCondition.LESS_THAN_OR_EQUAL, param: bytes32(uint256(1e18))});
        bytes32 merkleRoot = generate_merkle_root(rules, execRule);
        bytes memory enableData = abi.encodePacked(sessionKey, merkleRoot, uint48(0), uint48(0), address(0));
        bytes32 digest = getTypedDataHash(
            address(kernel), Kernel.executeBatch.selector, 0, 0, address(sessionKeyValidator), address(0), enableData
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);

        op.signature = abi.encodePacked(
            bytes4(0x00000002),
            uint48(0),
            uint48(0),
            address(sessionKeyValidator),
            address(0),
            uint256(enableData.length),
            enableData,
            uint256(65),
            r,
            s,
            v
        );

        // since we use all of them

        //bytes[] memory proof;
        op.signature = bytes.concat(
            op.signature,
            abi.encodePacked(
                sessionKey, entryPoint.signUserOpHash(vm, sessionKeyPriv, op), generate_proofs(rules, execRule)
            )
        );
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        logGas(op);

        entryPoint.handleOps(ops, beneficiary);
    }
}
// Following code is adapted from https://github.com/dmfxyz/murky/blob/main/src/common/MurkyBase.sol.

function _getRoot(bytes32[] memory data) pure returns (bytes32) {
    require(data.length > 1);
    while (data.length > 1) {
        data = _hashLevel(data);
    }
    return data[0];
}

function _getProof(bytes32[] memory data, uint256 nodeIndex) pure returns (bytes32[] memory) {
    require(data.length > 1);

    bytes32[] memory result = new bytes32[](64);
    uint256 pos;

    while (data.length > 1) {
        unchecked {
            if (nodeIndex & 0x1 == 1) {
                result[pos] = data[nodeIndex - 1];
            } else if (nodeIndex + 1 == data.length) {
                result[pos] = bytes32(0);
            } else {
                result[pos] = data[nodeIndex + 1];
            }
            ++pos;
            nodeIndex /= 2;
        }
        data = _hashLevel(data);
    }
    // Resize the length of the array to fit.
    /// @solidity memory-safe-assembly
    assembly {
        mstore(result, pos)
    }

    return result;
}

function _hashLevel(bytes32[] memory data) pure returns (bytes32[] memory) {
    bytes32[] memory result;
    unchecked {
        uint256 length = data.length;
        if (length & 0x1 == 1) {
            result = new bytes32[](length / 2 + 1);
            result[result.length - 1] = _hashPair(data[length - 1], bytes32(0));
        } else {
            result = new bytes32[](length / 2);
        }
        uint256 pos = 0;
        for (uint256 i = 0; i < length - 1; i += 2) {
            result[pos] = _hashPair(data[i], data[i + 1]);
            ++pos;
        }
    }
    return result;
}

function _hashPair(bytes32 left, bytes32 right) pure returns (bytes32 result) {
    /// @solidity memory-safe-assembly
    assembly {
        switch lt(left, right)
        case 0 {
            mstore(0x0, right)
            mstore(0x20, left)
        }
        default {
            mstore(0x0, left)
            mstore(0x20, right)
        }
        result := keccak256(0x0, 0x40)
    }
}
