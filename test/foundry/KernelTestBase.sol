// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IEntryPoint} from "I4337/interfaces/IEntryPoint.sol";
import {ENTRYPOINT_0_6_ADDRESS, ENTRYPOINT_0_6_BYTECODE} from "I4337/artifacts/EntryPoint_0_6.sol";
import {CREATOR_0_6_BYTECODE, CREATOR_0_6_ADDRESS} from "I4337/artifacts/EntryPoint_0_6.sol";
import {UserOperation} from "I4337/interfaces/UserOperation.sol";
import {Kernel} from "src/Kernel.sol";
import {Operation} from "src/common/Enums.sol";
import {Compatibility} from "src/abstract/Compatibility.sol";
import {KernelStorage} from "src/abstract/KernelStorage.sol";
import {KernelFactory} from "src/factory/KernelFactory.sol";
import {IKernelValidator} from "src/interfaces/IValidator.sol";

import {Call,ExecutionDetail} from "src/common/Structs.sol";
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
 
    Kernel kernel;
    Kernel kernelImpl;
    KernelFactory factory;
    IEntryPoint entryPoint;
    IKernelValidator defaultValidator;
    address owner;
    uint256 ownerKey;
    address payable beneficiary;
    address factoryOwner;

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

    function getOwners() internal virtual returns(address[] memory _owners);

    function test_external_call_execute_success() external {
        address[] memory validCallers = getOwners();
        for(uint i = 0; i<validCallers.length; i++) {
            vm.prank(validCallers[i]);
            kernel.execute(validCallers[i], 0, "", Operation.Call);
        }
    }
    
    function test_external_call_execute_fail() external {
        address[] memory validCallers = getOwners();
        for(uint i = 0; i<validCallers.length; i++) {
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

    function test_eip712() external {
        (bytes1 fields, string memory name, string memory version, ,address verifyingContract, bytes32 salt, ) = kernel.eip712Domain();
        assertEq(fields, bytes1(hex"0f"));
        assertEq(name, "Kernel");
        assertEq(version, "0.2.2");
        assertEq(verifyingContract, address(kernel));
        assertEq(salt, bytes32(0));
    }

    function test_external_call_default() external {
        vm.startPrank(owner);
        (bool success,) = address(kernel).call(abi.encodePacked("Hello world"));
        assertEq(success, true);
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

    function test_should_emit_event_on_receive() external {
        vm.expectEmit(address(kernel));
        emit Received(address(this), 1000);
        (bool success, ) = address(kernel).call{value: 1000}("");
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
        TestValidator newValidator = new TestValidator();
        bytes memory empty;
        UserOperation memory op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(KernelStorage.setDefaultValidator.selector, address(newValidator), empty)
        );
        op.signature = signUserOp(op);
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);
        assertEq(address(KernelStorage(address(kernel)).getDefaultValidator()), address(newValidator));
    }

    function test_disable_mode() external {
        vm.warp(1000);
        bytes memory empty;
        UserOperation memory op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(KernelStorage.disableMode.selector, bytes4(0x00000001), address(0), empty)
        );
        op.signature = signUserOp(op);
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);
        assertEq(uint256(bytes32(KernelStorage(address(kernel)).getDisabledMode())), 1 << 224);
    }

    function test_set_execution() external {
        TestValidator newValidator = new TestValidator();
        UserOperation memory op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(
                KernelStorage.setExecution.selector,
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
        ExecutionDetail memory execution = KernelStorage(address(kernel)).getExecution(bytes4(0xdeadbeef));
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
                KernelStorage.setExecution.selector,
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
        ExecutionDetail memory execution = KernelStorage(address(kernel)).getExecution(bytes4(0xdeadbeef));
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
            address(kernel),
            abi.encodeWithSelector(KernelStorage.disableMode.selector, bytes4(0x00000001), address(0), empty)
        );
        op.signature = signUserOp(op);
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        entryPoint.handleOps(ops, beneficiary);

        // try to run with mode 0x00000001
        op = entryPoint.fillUserOp(
            address(kernel), abi.encodeWithSelector(KernelStorage.disableMode.selector, bytes4(0x00000001))
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
        vm.expectRevert(Kernel.NotEntryPoint.selector);
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
        logGas(op);
        entryPoint.handleOps(ops, beneficiary);
    }
    
    function test_mock_mode_2() external {
        TestValidator testValidator = new TestValidator();
        TestExecutor testExecutor = new TestExecutor();
        UserOperation memory op =
            entryPoint.fillUserOp(address(kernel), abi.encodeWithSelector(TestExecutor.doNothing.selector));

        bytes32 digest = getTypedDataHash(
            address(kernel), TestExecutor.doNothing.selector, 0, 0, address(testValidator), address(testExecutor), ""
        );
        bytes memory sig = signHash(digest);

        op.signature = abi.encodePacked(
            bytes4(0x00000002),
            uint48(0),
            uint48(0),
            address(testValidator),
            address(testExecutor),
            uint256(0),
            uint256(65),
            sig
        );
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        // vm.expectEmit(true, false, false, false);
        // emit TestValidator.TestValidateUserOp(opHash);
        logGas(op);

        entryPoint.handleOps(ops, beneficiary);
    }

    function test_mock_mode_2_then_mode_1() external {
        TestValidator testValidator = new TestValidator();
        TestExecutor testExecutor = new TestExecutor();
        UserOperation memory op =
            entryPoint.fillUserOp(address(kernel), abi.encodeWithSelector(TestExecutor.doNothing.selector));

        bytes32 digest = getTypedDataHash(
            address(kernel), TestExecutor.doNothing.selector, 0, 0, address(testValidator), address(testExecutor), ""
        );
        bytes memory sig = signHash(digest);

        op.signature = abi.encodePacked(
            bytes4(0x00000002),
            uint48(0),
            uint48(0),
            address(testValidator),
            address(testExecutor),
            uint256(0),
            uint256(65),
            sig
        );
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        // vm.expectEmit(true, false, false, false);
        // emit TestValidator.TestValidateUserOp(opHash);
        entryPoint.handleOps(ops, beneficiary);
        op = entryPoint.fillUserOp(address(kernel), abi.encodeWithSelector(TestExecutor.doNothing.selector));
        // registered
        op.signature = abi.encodePacked(bytes4(0x00000001));
        ops[0] = op;
        logGas(op);
        entryPoint.handleOps(ops, beneficiary);
    }

    function getInitializeData() internal view virtual returns (bytes memory);

    function signUserOp(UserOperation memory op) internal view virtual returns (bytes memory);

    function signHash(bytes32 hash) internal view virtual returns (bytes memory);

    function _setAddress() internal {
        kernel = Kernel(payable(address(factory.createAccount(address(kernelImpl), getInitializeData(), 0))));
        vm.deal(address(kernel), 1e30);
    }

    function logGas(UserOperation memory op) internal returns (uint256 used) {
        try this.consoleGasUsage(op) {
            revert("should revert");
        } catch Error(string memory reason) {
            used = abi.decode(bytes(reason), (uint256));
            console.log("validation gas usage :", used);
        }
    }

    function consoleGasUsage(UserOperation memory op) external {
        uint256 gas = gasleft();
        vm.startPrank(address(entryPoint));
        kernel.validateUserOp(op, entryPoint.getUserOpHash(op), 0);
        vm.stopPrank();
        revert(string(abi.encodePacked(gas - gasleft())));
    }

    // computes the hash of the fully encoded EIP-712 message for the domain, which can be used to recover the signer
    function getTypedDataHash(
        address sender,
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
                ERC4337Utils._buildDomainSeparator("Kernel", "0.2.2", sender),
                ERC4337Utils.getStructHash(sig, validUntil, validAfter, validator, executor, enableData)
            )
        );
    }
}
