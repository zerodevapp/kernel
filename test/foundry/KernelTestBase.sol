// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IEntryPoint} from "I4337/interfaces/IEntryPoint.sol";
import {ENTRYPOINT_0_6_ADDRESS, ENTRYPOINT_0_6_BYTECODE} from "I4337/artifacts/EntryPoint_0_6.sol";
import {CREATOR_0_6_BYTECODE, CREATOR_0_6_ADDRESS} from "I4337/artifacts/EntryPoint_0_6.sol";
import {UserOperation} from "I4337/interfaces/UserOperation.sol";
import {Kernel} from "src/Kernel.sol";
import {Operation} from "src/common/Enums.sol";
import {Compatibility} from "src/abstract/Compatibility.sol";
import {IKernel} from "src/interfaces/IKernel.sol";
import {KernelFactory} from "src/factory/KernelFactory.sol";
import {IKernelValidator} from "src/interfaces/IKernelValidator.sol";

import {Call, ExecutionDetail} from "src/common/Structs.sol";
import {ValidationData, ValidUntil, ValidAfter} from "src/common/Types.sol";

import {ERC4337Utils} from "test/foundry/utils/ERC4337Utils.sol";
import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/Console.sol";
import {TestValidator} from "./mock/TestValidator.sol";
import {TestExecutor} from "./mock/TestExecutor.sol";
import {TestERC721} from "./mock/TestERC721.sol";
import {TestERC1155} from "./mock/TestERC1155.sol";

using ERC4337Utils for IEntryPoint;

abstract contract KernelTestBase is Test {
    // to support 0.8.19
    // also, weird error came up when i did Compatibility.Received
    event Received(address sender, uint256 amount);
    event UserOperationEvent(
        bytes32 indexed userOpHash,
        address indexed sender,
        address indexed paymaster,
        uint256 nonce,
        bool success,
        uint256 actualGasCost,
        uint256 actualGasUsed
    );
    event Upgraded(address indexed newImplementation);

    Kernel kernel;
    Kernel kernelImpl;
    KernelFactory factory;
    IEntryPoint entryPoint;
    IKernelValidator defaultValidator;
    address owner;
    uint256 ownerKey;
    address payable beneficiary;
    address factoryOwner;

    bytes4 executionSig;
    ExecutionDetail executionDetail;

    function _initialize() internal {
        (owner, ownerKey) = makeAddrAndKey("owner");
        (factoryOwner,) = makeAddrAndKey("factoryOwner");
        beneficiary = payable(address(makeAddr("beneficiary")));
        vm.etch(ENTRYPOINT_0_6_ADDRESS, ENTRYPOINT_0_6_BYTECODE);
        entryPoint = IEntryPoint(payable(ENTRYPOINT_0_6_ADDRESS));
        vm.etch(CREATOR_0_6_ADDRESS, CREATOR_0_6_BYTECODE);
        kernelImpl = new Kernel(entryPoint);
        factory = new KernelFactory(factoryOwner, entryPoint);
        vm.startPrank(factoryOwner);
        factory.setImplementation(address(kernelImpl), true);
        vm.stopPrank();
    }

    function _setExecutionDetail() internal virtual;

    function getEnableData() internal view virtual returns (bytes memory);

    function getValidatorSignature(UserOperation memory op) internal view virtual returns (bytes memory);

    function getOwners() internal virtual returns (address[] memory _owners);

    function getInitializeData() internal view virtual returns (bytes memory);

    function signUserOp(UserOperation memory op) internal view virtual returns (bytes memory);

    function getWrongSignature(UserOperation memory op) internal view virtual returns (bytes memory);

    function signHash(bytes32 hash) internal view virtual returns (bytes memory);

    function getWrongSignature(bytes32 hash) internal view virtual returns (bytes memory);

    function test_default_validator_enable() external virtual;

    function test_default_validator_disable() external virtual;

    function test_external_call_execute_success() external {
        address[] memory validCallers = getOwners();
        for (uint256 i = 0; i < validCallers.length; i++) {
            vm.prank(validCallers[i]);
            kernel.execute(validCallers[i], 0, "", Operation.Call);
        }
    }

    function test_external_call_execute_delegatecall_fail() external {
        address[] memory validCallers = getOwners();
        for (uint256 i = 0; i < validCallers.length; i++) {
            vm.prank(validCallers[i]);
            vm.expectRevert();
            kernel.execute(validCallers[i], 0, "", Operation.DelegateCall);
        }
    }

    function test_external_call_execute_fail() external {
        address[] memory validCallers = getOwners();
        for (uint256 i = 0; i < validCallers.length; i++) {
            vm.prank(address(uint160(validCallers[i]) + 1));
            vm.expectRevert();
            kernel.execute(validCallers[i], 0, "", Operation.Call);
        }
    }

    function test_external_call_batch_execute_success() external {
        Call[] memory calls = new Call[](1);
        calls[0] = Call(owner, 0, "");
        vm.prank(owner);
        kernel.executeBatch(calls);
    }

    function test_external_call_batch_execute_fail() external {
        Call[] memory calls = new Call[](1);
        calls[0] = Call(owner, 0, "");
        vm.prank(address(uint160(owner) - 1));
        vm.expectRevert();
        kernel.executeBatch(calls);
    }

    function test_get_nonce() external {
        assertEq(kernel.getNonce(), entryPoint.getNonce(address(kernel), 0));
        assertEq(kernel.getNonce(100), entryPoint.getNonce(address(kernel), 100));
    }

    function test_get_nonce(uint192 key) external {
        assertEq(kernel.getNonce(key), entryPoint.getNonce(address(kernel), key));
    }

    function test_eip712() external {
        (bytes1 fields, string memory name, string memory version,, address verifyingContract, bytes32 salt,) =
            kernel.eip712Domain();
        assertEq(fields, bytes1(hex"0f"));
        assertEq(name, "Kernel");
        assertEq(version, "0.2.2");
        assertEq(verifyingContract, address(kernel));
        assertEq(salt, bytes32(0));
    }

    function test_upgrade() external {
        vm.startPrank(address(entryPoint));
        vm.expectEmit(true, false, false, false, address(kernel));
        emit Upgraded(address(0xdeadbeef));
        kernel.upgradeTo(address(0xdeadbeef));
    }

    function test_external_call_default() external {
        vm.startPrank(owner);
        (bool success,) = address(kernel).call(abi.encodePacked("Hello world"));
        assertEq(success, true);
    }

    function test_initialize() external {
        factory.createAccount(address(kernelImpl), getInitializeData(), 1);
    }

    function test_initialize_twice() external {
        (bool success,) = address(kernel).call(getInitializeData());
        assertEq(success, false);
    }

    function test_should_return_address_if_deployed() external {
        address proxy = factory.createAccount(address(kernelImpl), getInitializeData(), 0);
        assertEq(proxy, address(kernel));
    }

    function test_validate_signature() external {
        bytes32 hash = keccak256(abi.encodePacked("hello world"));
        bytes memory sig = signHash(hash);
        assertEq(kernel.isValidSignature(hash, sig), Kernel.isValidSignature.selector);
    }

    function test_fail_validate_wrongsignature() external {
        bytes32 hash = keccak256(abi.encodePacked("hello world"));
        bytes memory sig = getWrongSignature(hash);
        assertEq(kernel.isValidSignature(hash, sig), bytes4(0xffffffff));
    }

    function test_fail_validate_not_activate() external virtual {
        TestValidator newDefaultValidator = new TestValidator();
        vm.startPrank(address(entryPoint));
        kernel.setDefaultValidator(newDefaultValidator, "");
        vm.stopPrank();

        newDefaultValidator.setData(false, 0, 0);

        vm.warp(100000);

        bytes32 hash = keccak256(abi.encodePacked("hello world"));
        assertEq(kernel.isValidSignature(hash, ""), bytes4(0xffffffff));
        newDefaultValidator.setData(true, uint48(block.timestamp + 1000), uint48(0));
        assertEq(kernel.isValidSignature(hash, ""), bytes4(0xffffffff));
        newDefaultValidator.setData(true, uint48(0), uint48(block.timestamp - 1000));
        assertEq(kernel.isValidSignature(hash, ""), bytes4(0xffffffff));
    }

    function test_should_emit_event_on_receive() external {
        vm.expectEmit(address(kernel));
        emit Received(address(this), 1000);
        (bool success,) = address(kernel).call{value: 1000}("");
        assertEq(success, true);
    }

    function test_should_receive_erc721() external {
        TestERC721 token = new TestERC721();
        token.safeMint(address(kernel), 1);
    }

    function test_should_receive_erc1155() external {
        TestERC1155 token = new TestERC1155();
        token.mint(address(kernel), 1, 1000, "");
    }

    function test_should_receive_erc1155_batch() external {
        TestERC1155 token = new TestERC1155();
        uint256[] memory ids = new uint256[](2);
        ids[0] = 1;
        ids[1] = 2;
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 1000;
        amounts[1] = 1000;
        token.batchMint(address(kernel), ids, amounts, "");
    }

    function test_set_default_validator() external virtual {
        TestValidator newDefaultValidator = new TestValidator();
        bytes memory empty;
        UserOperation memory op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(IKernel.setDefaultValidator.selector, address(newDefaultValidator), empty)
        );
        op.signature = signUserOp(op);
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);
        assertEq(address(IKernel(address(kernel)).getDefaultValidator()), address(newDefaultValidator));
    }

    function test_disable_mode() external {
        vm.warp(1000);
        bytes memory empty;
        UserOperation memory op = entryPoint.fillUserOp(
            address(kernel), abi.encodeWithSelector(IKernel.disableMode.selector, bytes4(0x00000001), address(0), empty)
        );
        op.signature = signUserOp(op);
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);
        assertEq(uint256(bytes32(IKernel(address(kernel)).getDisabledMode())), 1 << 224);
        assertEq(uint256(IKernel(address(kernel)).getLastDisabledTime()), block.timestamp);
    }

    function test_set_execution() external {
        TestValidator newValidator = new TestValidator();
        UserOperation memory op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(
                IKernel.setExecution.selector,
                bytes4(0xdeadbeef),
                address(0xdead),
                address(newValidator),
                uint48(0),
                uint48(0),
                bytes("")
            )
        );
        op.signature = signUserOp(op);
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);
        ExecutionDetail memory execution = IKernel(address(kernel)).getExecution(bytes4(0xdeadbeef));
        assertEq(execution.executor, address(0xdead));
        assertEq(address(execution.validator), address(newValidator));
        assertEq(uint256(ValidUntil.unwrap(execution.validUntil)), uint256(0));
        assertEq(uint256(ValidAfter.unwrap(execution.validAfter)), uint256(0));
    }

    function test_external_call_execution() external {
        TestValidator newValidator = new TestValidator();
        UserOperation memory op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(
                IKernel.setExecution.selector,
                bytes4(0xdeadbeef),
                address(0xdead),
                address(newValidator),
                uint48(0),
                uint48(0),
                bytes("")
            )
        );
        op.signature = signUserOp(op);
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);
        ExecutionDetail memory execution = IKernel(address(kernel)).getExecution(bytes4(0xdeadbeef));
        assertEq(execution.executor, address(0xdead));
        assertEq(address(execution.validator), address(newValidator));
        assertEq(uint256(ValidUntil.unwrap(execution.validUntil)), uint256(0));
        assertEq(uint256(ValidAfter.unwrap(execution.validAfter)), uint256(0));

        address randomAddr = makeAddr("random");
        newValidator.sudoSetCaller(address(kernel), randomAddr);
        vm.startPrank(randomAddr);
        (bool success,) = address(kernel).call(abi.encodePacked(bytes4(0xdeadbeef)));
        assertEq(success, true);
        vm.stopPrank();

        address notAllowed = makeAddr("notAllowed");
        vm.startPrank(notAllowed);
        (bool success2,) = address(kernel).call(abi.encodePacked(bytes4(0xdeadbeef)));
        assertEq(success2, false);
        vm.stopPrank();
    }

    function test_revert_when_mode_disabled() external {
        vm.warp(1000);
        bytes memory empty;
        UserOperation memory op = entryPoint.fillUserOp(
            address(kernel), abi.encodeWithSelector(IKernel.disableMode.selector, bytes4(0x00000001), address(0), empty)
        );
        op.signature = signUserOp(op);
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);

        // try to run with mode 0x00000001
        op = entryPoint.fillUserOp(
            address(kernel), abi.encodeWithSelector(IKernel.disableMode.selector, bytes4(0x00000001))
        );
        op.signature = abi.encodePacked(bytes4(0x00000001), entryPoint.signUserOpHash(vm, ownerKey, op));
        ops[0] = op;

        vm.expectRevert(
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, string.concat("AA23 reverted (or OOG)"))
        );
        entryPoint.handleOps(ops, beneficiary);
    }

    // validate user op
    function test_validateUserOp_fail_not_entryPoint() external {
        UserOperation memory op =
            entryPoint.fillUserOp(address(kernel), abi.encodeWithSelector(TestExecutor.doNothing.selector));
        op.signature = signUserOp(op);
        vm.expectRevert(IKernel.NotEntryPoint.selector);
        kernel.validateUserOp(op, bytes32(hex"deadbeef"), uint256(100));
    }

    function test_validateUserOp_fail_invalid_mode() external {
        UserOperation memory op =
            entryPoint.fillUserOp(address(kernel), abi.encodeWithSelector(TestExecutor.doNothing.selector));
        op.signature = hex"00000003";
        vm.prank(address(entryPoint));
        ValidationData res = kernel.validateUserOp(op, bytes32(hex"deadbeef"), uint256(100));
        assertEq(ValidationData.unwrap(res), 1);
    }

    function test_sudo() external {
        UserOperation memory op =
            entryPoint.fillUserOp(address(kernel), abi.encodeWithSelector(TestExecutor.doNothing.selector));
        op.signature = signUserOp(op);
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);
    }

    function test_sudo_wrongSig() external {
        UserOperation memory op =
            entryPoint.fillUserOp(address(kernel), abi.encodeWithSelector(TestExecutor.doNothing.selector));
        op.signature = getWrongSignature(op);
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        vm.expectRevert();
        entryPoint.handleOps(ops, beneficiary);
    }

    // mode 2 tests
    function test_mode_2() public {
        UserOperation memory op = entryPoint.fillUserOp(address(kernel), abi.encodePacked(executionSig));

        op.signature = buildEnableSignature(
            op, executionSig, uint48(0), uint48(0), executionDetail.validator, executionDetail.executor
        );
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        vm.expectEmit(true, true, true, false, address(entryPoint));
        emit UserOperationEvent(entryPoint.getUserOpHash(op), address(kernel), address(0), op.nonce, false, 0, 0);
        entryPoint.handleOps(ops, beneficiary);
    }

    function buildEnableSignature(
        UserOperation memory op,
        bytes4 selector,
        uint48 validAfter,
        uint48 validUntil,
        IKernelValidator validator,
        address executor
    ) internal view returns (bytes memory sig) {
        require(address(executionDetail.validator) != address(0), "execution detail not set");
        bytes memory enableData = getEnableData();
        bytes32 digest = getTypedDataHash(selector, validAfter, validUntil, address(validator), executor, enableData);
        bytes memory enableSig = signHash(digest);
        sig = getValidatorSignature(op);
        sig = abi.encodePacked(
            bytes4(0x00000002),
            validAfter,
            validUntil,
            address(validator),
            executor,
            uint256(enableData.length),
            enableData,
            enableSig.length,
            enableSig,
            sig
        );
    }

    function test_enable_then_mode_1() public {
        UserOperation memory op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(
                IKernel.setExecution.selector,
                executionSig,
                executionDetail.executor,
                executionDetail.validator,
                ValidUntil.wrap(0),
                ValidAfter.wrap(0),
                getEnableData()
            )
        );
        op.signature = signUserOp(op);
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;

        entryPoint.handleOps(ops, beneficiary);
        // vm.expectEmit(true, false, false, false);
        // emit TestValidator.TestValidateUserOp(opHash);
        op = entryPoint.fillUserOp(address(kernel), abi.encodeWithSelector(executionSig));
        // registered
        op.signature = abi.encodePacked(bytes4(0x00000001), getValidatorSignature(op));
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);
    }

    function _setAddress() internal {
        kernel = Kernel(payable(address(factory.createAccount(address(kernelImpl), getInitializeData(), 0))));
        vm.deal(address(kernel), 1e30);
    }

    // computes the hash of the fully encoded EIP-712 message for the domain, which can be used to recover the signer
    function getTypedDataHash(
        bytes4 sig,
        uint48 validUntil,
        uint48 validAfter,
        address validator,
        address executor,
        bytes memory enableData
    ) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                ERC4337Utils._buildDomainSeparator("Kernel", "0.2.2", address(kernel)),
                ERC4337Utils.getStructHash(sig, validUntil, validAfter, validator, executor, enableData)
            )
        );
    }
}
