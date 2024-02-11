pragma solidity ^0.8.0;

import {IEntryPoint} from "I4337/interfaces/IEntryPoint.sol";
import "src/Kernel.sol";
import "src/validator/WeightedECDSAValidator.sol";
// test artifacts
// test utils
import "forge-std/Test.sol";
import {ERC4337Utils} from "src/utils/ERC4337Utils.sol";
import {KernelTestBase} from "src/utils/KernelTestBase.sol";
import {TestExecutor} from "src/mock/TestExecutor.sol";
import {TestValidator} from "src/mock/TestValidator.sol";
import {IKernel} from "src/interfaces/IKernel.sol";

using ERC4337Utils for IEntryPoint;

contract KernelWeightedECDSATest is KernelTestBase {
    address[] public owners;
    uint256[] public ownerKeys;
    uint24[] public weights;
    uint24 public threshold;
    uint48 public delay;

    function setUp() public virtual {
        _initialize();
        defaultValidator = new WeightedECDSAValidator();
        owners = new address[](3);
        ownerKeys = new uint256[](3);
        (owners[0], ownerKeys[0]) = makeAddrAndKey("owner0");
        (owners[1], ownerKeys[1]) = makeAddrAndKey("owner1");
        (owners[2], ownerKeys[2]) = makeAddrAndKey("owner2");
        // sort owners and keys from largest to smallest owner address
        for (uint256 i = 0; i < owners.length; i++) {
            for (uint256 j = i + 1; j < owners.length; j++) {
                if (owners[i] < owners[j]) {
                    address tempAddr = owners[i];
                    owners[i] = owners[j];
                    owners[j] = tempAddr;
                    uint256 tempKey = ownerKeys[i];
                    ownerKeys[i] = ownerKeys[j];
                    ownerKeys[j] = tempKey;
                }
            }
        }
        weights = [uint24(1), uint24(2), uint24(3)];
        threshold = 3;
        delay = 0;
        _setAddress();
        _setExecutionDetail();
    }

    function test_ignore() external {}

    function _setExecutionDetail() internal virtual override {
        executionDetail.executor = address(new TestExecutor());
        executionSig = TestExecutor.doNothing.selector;
        executionDetail.validator = new TestValidator();
    }

    function getEnableData() internal view virtual override returns (bytes memory) {
        return "";
    }

    function getValidatorSignature(UserOperation memory) internal view virtual override returns (bytes memory) {
        return "";
    }

    function getOwners() internal view override returns (address[] memory) {
        return owners;
    }

    function getInitializeData() internal view override returns (bytes memory) {
        bytes memory data = abi.encode(owners, weights, threshold, delay);
        return abi.encodeWithSelector(KernelStorage.initialize.selector, defaultValidator, data);
    }

    function test_external_call_execute_success() external override {
        vm.skip(true);
    }

    function test_external_call_default() external override {
        vm.skip(true);
    }

    function test_external_call_execute_delegatecall_success() external override {
        vm.skip(true);
    }

    function test_external_call_batch_execute_success() external override {
        vm.skip(true);
    }

    function signUserOp(UserOperation memory op) internal view override returns (bytes memory) {
        bytes32 calldataAndNonceHash = keccak256(abi.encode(op.sender, op.callData, op.nonce));

        bytes32 digest = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("WeightedECDSAValidator"),
                keccak256("0.0.3"),
                block.chainid,
                address(defaultValidator)
            )
        );

        bytes32 structHash =
            keccak256(abi.encode(keccak256("Approve(bytes32 callDataAndNonceHash)"), calldataAndNonceHash));
        assembly {
            // Compute the digest.
            mstore(0x00, 0x1901000000000000) // Store "\x19\x01".
            mstore(0x1a, digest) // Store the domain separator.
            mstore(0x3a, structHash) // Store the struct hash.
            digest := keccak256(0x18, 0x42)
            // Restore the part of the free memory slot that was overwritten.
            mstore(0x3a, 0)
        }

        (uint8 v0, bytes32 r0, bytes32 s0) = vm.sign(ownerKeys[0], digest);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(ownerKeys[1], digest);
        bytes memory opSig = entryPoint.signUserOpHash(vm, ownerKeys[2], op);
        return abi.encodePacked(bytes4(0x00000000), r0, s0, v0, r1, s1, v1, opSig);
    }

    function getWrongSignature(UserOperation memory op) internal view override returns (bytes memory) {
        return abi.encodePacked(bytes4(0x00000000), entryPoint.signUserOpHash(vm, ownerKeys[0], op));
    }

    function signHash(bytes32 hash) internal view override returns (bytes memory) {
        (uint8 v0, bytes32 r0, bytes32 s0) = vm.sign(ownerKeys[0], hash);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(ownerKeys[1], hash);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(ownerKeys[2], hash);
        return abi.encodePacked(r0, s0, v0, r1, s1, v1, r2, s2, v2);
    }

    function getWrongSignature(bytes32 hash) internal view override returns (bytes memory) {
        (uint8 v0, bytes32 r0, bytes32 s0) = vm.sign(ownerKeys[1], hash);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(ownerKeys[0], hash);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(ownerKeys[2], hash);
        return abi.encodePacked(r0, s0, v0, r1, s1, v1, r2, s2, v2);
    }

    function test_default_validator_enable() external override {
        //UserOperation memory op = buildUserOperation(
        //    abi.encodeWithSelector(
        //        IKernel.execute.selector,
        //        address(defaultValidator),
        //        0,
        //        abi.encodeWithSelector(ECDSAValidator.enable.selector, abi.encodePacked(address(0xdeadbeef))),
        //        Operation.Call
        //    )
        //);
        //performUserOperationWithSig(op);
        //(address owner) = ECDSAValidator(address(defaultValidator)).ecdsaValidatorStorage(address(kernel));
        //assertEq(owner, address(0xdeadbeef), "owner should be 0xdeadbeef");
    }

    function test_default_validator_disable() external override {
        UserOperation memory op = buildUserOperation(
            abi.encodeWithSelector(
                IKernel.execute.selector,
                address(defaultValidator),
                0,
                abi.encodeWithSelector(WeightedECDSAValidator.disable.selector, ""),
                Operation.Call
            )
        );
        performUserOperationWithSig(op);
    }
}
