// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "src/factory/AdminLessERC1967Factory.sol";
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
import "test/foundry/utils/ERC4337Utils.sol";
// test actions/validators
import "src/validator/SessionKeyValidator.sol";

using ERC4337Utils for EntryPoint;

contract SessionKeyValidatorTest is KernelTestBase {
    ExecuteSessionKeyValidator sessionKeyValidator;
    TestERC20 testToken;
    address sessionKey;
    uint256 sessionKeyPriv;

    function setUp() public {
        (owner, ownerKey) = makeAddrAndKey("owner");
        (factoryOwner,) = makeAddrAndKey("factoryOwner");
        (sessionKey, sessionKeyPriv) = makeAddrAndKey("sessionKey");
        entryPoint = new EntryPoint();
        kernelImpl = new Kernel(entryPoint);
        factory = new KernelFactory(factoryOwner, entryPoint);
        vm.startPrank(factoryOwner);
        factory.setImplementation(address(kernelImpl), true);
        vm.stopPrank();

        validator = new ECDSAValidator();

        kernel = Kernel(
            payable(
                address(
                    factory.createAccount(
                        address(kernelImpl),
                        abi.encodeWithSelector(KernelStorage.initialize.selector, validator, abi.encodePacked(owner)),
                        0
                    )
                )
            )
        );
        vm.deal(address(kernel), 1e30);
        beneficiary = payable(address(makeAddr("beneficiary")));
        testToken = new TestERC20();
        sessionKeyValidator = new ExecuteSessionKeyValidator();
    }

    function test_mode_2_no_paymaster() external {
        testToken.mint(address(kernel), 100e18);
        TestERC20 testToken2 = new TestERC20();
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
        rules[0] = ParamRule({offset: 32, condition: ParamCondition.LESS_THAN_OR_EQUAL, param: bytes32(uint256(1e18))});

        bytes32[] memory data = new bytes32[](2);
        data[0] = keccak256(
            abi.encode(
                Permission({
                    valueLimit: 0,
                    target: address(testToken),
                    sig: ERC20.transfer.selector,
                    operation: Operation.Call,
                    rules: rules
                })
            )
        );

        data[1] = keccak256(
            abi.encode(
                Permission({
                    valueLimit: 0,
                    target: address(testToken2),
                    sig: ERC20.transfer.selector,
                    operation: Operation.Call,
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
                        valueLimit: 0,
                        target: address(testToken),
                        sig: ERC20.transfer.selector,
                        operation: Operation.Call,
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

    function test_mode_2_no_paymaster_delegate_call() external {
        testToken.mint(address(kernel), 100e18);
        TestERC20 testToken2 = new TestERC20();
        UserOperation memory op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(
                Kernel.execute.selector,
                address(testToken),
                0,
                abi.encodeWithSelector(ERC20.transfer.selector, beneficiary, 100),
                Operation.DelegateCall
            )
        );

        ParamRule[] memory rules = new ParamRule[](1);
        rules[0] = ParamRule({offset: 32, condition: ParamCondition.LESS_THAN_OR_EQUAL, param: bytes32(uint256(1e18))});

        bytes32[] memory data = new bytes32[](2);
        data[0] = keccak256(
            abi.encode(
                Permission({
                    valueLimit: 0,
                    target: address(testToken),
                    sig: ERC20.transfer.selector,
                    operation: Operation.DelegateCall,
                    rules: rules
                })
            )
        );

        data[1] = keccak256(
            abi.encode(
                Permission({
                    valueLimit: 0,
                    target: address(testToken2),
                    sig: ERC20.transfer.selector,
                    operation: Operation.Call,
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
                        valueLimit: 0,
                        target: address(testToken),
                        sig: ERC20.transfer.selector,
                        operation: Operation.DelegateCall,
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

    function test_mode_2_no_paymaster_wrong_param() external {
        testToken.mint(address(kernel), 100e18);
        TestERC20 testToken2 = new TestERC20();
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
        rules[0] = ParamRule({offset: 32, condition: ParamCondition.LESS_THAN_OR_EQUAL, param: bytes32(uint256(1e18))});

        bytes32[] memory data = new bytes32[](2);
        data[0] = keccak256(
            abi.encode(
                Permission({
                    valueLimit: 0,
                    target: address(testToken),
                    sig: ERC20.transfer.selector,
                    operation: Operation.Call,
                    rules: rules
                })
            )
        );

        data[1] = keccak256(
            abi.encode(
                Permission({
                    valueLimit: 0,
                    target: address(testToken2),
                    sig: ERC20.transfer.selector,
                    operation: Operation.Call,
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
                        valueLimit: 0,
                        target: address(testToken),
                        sig: ERC20.transfer.selector,
                        operation: Operation.DelegateCall,
                        rules: rules
                    }),
                    _getProof(data, 0)
                )
            )
        );
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        logGas(op);

        vm.expectRevert();
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
