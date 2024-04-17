// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IEntryPoint} from "I4337/interfaces/IEntryPoint.sol";
import {ENTRYPOINT_0_6_ADDRESS, ENTRYPOINT_0_6_BYTECODE} from "I4337/artifacts/EntryPoint_0_6.sol";
import {CREATOR_0_6_BYTECODE, CREATOR_0_6_ADDRESS} from "I4337/artifacts/EntryPoint_0_6.sol";
import {UserOperation} from "I4337/interfaces/UserOperation.sol";
import {Kernel} from "../Kernel.sol";
import {Operation} from "../common/Enums.sol";
import {Compatibility} from "../abstract/Compatibility.sol";
import {IKernel} from "../interfaces/IKernel.sol";
import {KernelFactory} from "../factory/KernelFactory.sol";
import {IKernelValidator} from "../interfaces/IKernelValidator.sol";

import {Call, ExecutionDetail} from "../common/Structs.sol";
import {ValidationData, ValidUntil, ValidAfter} from "../common/Types.sol";
import {KERNEL_VERSION, KERNEL_NAME} from "../common/Constants.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";

import {ERC4337Utils} from "./ERC4337Utils.sol";
import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {TestValidator} from "../mock/TestValidator.sol";
import {TestExecutor} from "../mock/TestExecutor.sol";
import {TestERC721} from "../mock/TestERC721.sol";
import {TestERC1155} from "../mock/TestERC1155.sol";
import {TestCallee} from "../mock/TestCallee.sol";

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

    function test_external_call_execute_success() external virtual {
        address[] memory validCallers = getOwners();
        for (uint256 i = 0; i < validCallers.length; i++) {
            vm.prank(validCallers[i]);
            kernel.execute(validCallers[i], 0, "", Operation.Call);
        }
    }

    function test_external_call_execute_delegatecall_success() external virtual {
        address[] memory validCallers = getOwners();
        for (uint256 i = 0; i < validCallers.length; i++) {
            vm.prank(validCallers[i]);
            kernel.executeDelegateCall(validCallers[i], "");
        }
    }

    function test_external_call_execute_delegatecall_fail() external virtual {
        address[] memory validCallers = getOwners();
        for (uint256 i = 0; i < validCallers.length; i++) {
            vm.prank(address(uint160(validCallers[i]) + 1));
            vm.expectRevert();
            kernel.executeDelegateCall(validCallers[i], "");
        }
    }

    function test_external_call_execute_delegatecall_option_fail() external {
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

    function test_external_call_batch_execute_success() external virtual {
        TestCallee callee = new TestCallee();
        Call[] memory calls = new Call[](3);
        calls[0] = Call(owner, 0, "");
        calls[1] = Call(address(callee), 0, abi.encodeWithSelector(callee.returnLong.selector));
        calls[2] = Call(address(callee), 0, abi.encode("HelloWorld"));
        vm.prank(owner);
        kernel.executeBatch(calls);
        assertEq(callee.caller(), address(kernel));
        assertEq(callee.sent(), 0);
        assertEq(keccak256(callee.message()), keccak256(abi.encode("HelloWorld")));
        calls = new Call[](3);
        calls[0] = Call(owner, 0, "");
        calls[1] = Call(address(callee), 0, abi.encodeWithSelector(callee.returnLongBytes.selector));
        calls[2] = Call(address(callee), 0, abi.encode("HelloWorld"));
        assertEq(callee.caller(), address(kernel));
        assertEq(callee.sent(), 0);
        assertEq(keccak256(callee.message()), keccak256(abi.encode("HelloWorld")));

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
        assertEq(name, KERNEL_NAME);
        assertEq(version, KERNEL_VERSION);
        assertEq(verifyingContract, address(kernel));
        assertEq(salt, bytes32(0));
    }

    function test_upgrade() external {
        vm.startPrank(address(entryPoint));
        vm.expectEmit(true, false, false, false, address(kernel));
        emit Upgraded(address(0xdeadbeef));
        kernel.upgradeTo(address(0xdeadbeef));
    }

    function test_external_call_default() external virtual {
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

    function test_validate_signature() external virtual {
        Kernel kernel2 = Kernel(payable(factory.createAccount(address(kernelImpl), getInitializeData(), 3)));
        string memory message = "hello world";
        bytes32 hash = ECDSA.toEthSignedMessageHash(bytes(message));
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01", ERC4337Utils._buildDomainSeparator(KERNEL_NAME, KERNEL_VERSION, address(kernel)), hash
            )
        );
        bytes memory sig = signHash(digest);
        vm.startPrank(makeAddr("app"));
        assertEq(kernel.isValidSignature(hash, sig), Kernel.isValidSignature.selector);
        assertEq(kernel2.isValidSignature(hash, sig), bytes4(0xffffffff));
        vm.stopPrank();
    }

    function test_fail_validate_wrongsignature() external virtual {
        bytes32 hash = keccak256(abi.encodePacked("hello world"));
        bytes memory sig = getWrongSignature(hash);
        vm.startPrank(makeAddr("app"));
        assertEq(kernel.isValidSignature(hash, sig), bytes4(0xffffffff));
        vm.stopPrank();
    }

    function test_fail_validate_not_activate() external virtual {
        TestValidator newDefaultValidator = new TestValidator();
        vm.startPrank(address(entryPoint));
        kernel.setDefaultValidator(newDefaultValidator, "");
        vm.stopPrank();

        newDefaultValidator.setData(false, 0, 0);

        vm.warp(100000);

        vm.startPrank(makeAddr("app"));
        bytes32 hash = keccak256(abi.encodePacked("hello world"));
        assertEq(kernel.isValidSignature(hash, ""), bytes4(0xffffffff));
        newDefaultValidator.setData(true, uint48(block.timestamp + 1000), uint48(0));
        assertEq(kernel.isValidSignature(hash, ""), bytes4(0xffffffff));
        newDefaultValidator.setData(true, uint48(0), uint48(block.timestamp - 1000));
        assertEq(kernel.isValidSignature(hash, ""), bytes4(0xffffffff));
        vm.stopPrank();
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
        UserOperation memory op = buildUserOperation(
            abi.encodeWithSelector(IKernel.setDefaultValidator.selector, address(newDefaultValidator), empty)
        );
        performUserOperationWithSig(op);
        assertEq(address(IKernel(address(kernel)).getDefaultValidator()), address(newDefaultValidator));
    }

    function test_disable_mode() external {
        vm.warp(1000);
        bytes memory empty;
        UserOperation memory op = buildUserOperation(
            abi.encodeWithSelector(IKernel.disableMode.selector, bytes4(0x00000001), address(0), empty)
        );
        performUserOperationWithSig(op);
        assertEq(uint256(bytes32(IKernel(address(kernel)).getDisabledMode())), 1 << 224);
        assertEq(uint256(IKernel(address(kernel)).getLastDisabledTime()), block.timestamp);
    }

    function test_set_execution() external {
        TestValidator newValidator = new TestValidator();
        UserOperation memory op = buildUserOperation(
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
        performUserOperationWithSig(op);
        ExecutionDetail memory execution = IKernel(address(kernel)).getExecution(bytes4(0xdeadbeef));
        assertEq(execution.executor, address(0xdead));
        assertEq(address(execution.validator), address(newValidator));
        assertEq(uint256(ValidUntil.unwrap(execution.validUntil)), uint256(0));
        assertEq(uint256(ValidAfter.unwrap(execution.validAfter)), uint256(0));
    }

    function test_external_call_execution() external virtual {
        TestValidator newValidator = new TestValidator();
        UserOperation memory op = buildUserOperation(
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
        performUserOperationWithSig(op);
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
        UserOperation memory op = buildUserOperation(
            abi.encodeWithSelector(IKernel.disableMode.selector, bytes4(0x00000001), address(0), empty)
        );
        performUserOperationWithSig(op);

        // try to run with mode 0x00000001
        op = buildUserOperation(abi.encodeWithSelector(IKernel.disableMode.selector, bytes4(0x00000001)));
        op.signature = abi.encodePacked(bytes4(0x00000001), entryPoint.signUserOpHash(vm, ownerKey, op));
        vm.expectRevert(
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, string.concat("AA23 reverted (or OOG)"))
        );
        performUserOperation(op);
    }

    // validate user op
    function test_validateUserOp_fail_not_entryPoint() external {
        UserOperation memory op = buildUserOperation(abi.encodeWithSelector(TestExecutor.doNothing.selector));
        vm.expectRevert(IKernel.NotEntryPoint.selector);
        kernel.validateUserOp(op, bytes32(hex"deadbeef"), uint256(100));
    }

    function test_validateUserOp_fail_invalid_mode() external {
        UserOperation memory op = buildUserOperation(abi.encodeWithSelector(TestExecutor.doNothing.selector));
        op.signature = hex"00000003";
        vm.prank(address(entryPoint));
        ValidationData res = kernel.validateUserOp(op, bytes32(hex"deadbeef"), uint256(100));
        assertEq(ValidationData.unwrap(res), 1);
    }

    function test_sudo() external {
        UserOperation memory op = buildUserOperation(abi.encodeWithSelector(TestExecutor.doNothing.selector));
        performUserOperationWithSig(op);
    }

    function test_sudo_wrongSig() external {
        UserOperation memory op = buildUserOperation(abi.encodeWithSelector(TestExecutor.doNothing.selector));
        op.signature = getWrongSignature(op);
        vm.expectRevert();
        performUserOperation(op);
    }

    // mode 2 tests
    function test_mode_2() public {
        UserOperation memory op = buildUserOperation(abi.encodePacked(executionSig));

        op.signature = buildEnableSignature(
            op, executionSig, uint48(0), uint48(0), executionDetail.validator, executionDetail.executor
        );
        vm.expectEmit(true, true, true, false, address(entryPoint));
        emit UserOperationEvent(entryPoint.getUserOpHash(op), address(kernel), address(0), op.nonce, false, 0, 0);
        performUserOperation(op);
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
        UserOperation memory op = buildUserOperation(
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
        performUserOperationWithSig(op);
        op = buildUserOperation(abi.encodeWithSelector(executionSig));
        op.signature = abi.encodePacked(bytes4(0x00000001), getValidatorSignature(op));
        performUserOperation(op);
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
                ERC4337Utils._buildDomainSeparator(KERNEL_NAME, KERNEL_VERSION, address(kernel)),
                ERC4337Utils.getStructHash(sig, validUntil, validAfter, validator, executor, enableData)
            )
        );
    }

    function buildUserOperation(bytes memory callData) internal view returns (UserOperation memory op) {
        return entryPoint.fillUserOp(address(kernel), callData);
    }

    function performUserOperationWithSig(UserOperation memory op) internal {
        op.signature = signUserOp(op);
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);
    }

    function performUserOperation(UserOperation memory op) internal {
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);
    }
}
