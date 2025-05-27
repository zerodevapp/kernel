pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {EntryPointLib} from "./utils/EntryPointLib.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Kernel} from "src/Kernel.sol";
import {SelectorManager} from "src/core/SelectorManager.sol";
import {KernelFactory} from "src/KernelFactory.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";
import {Install} from "src/types/Structs.sol";
import {MockFallback} from "./mock/MockFallback.sol";
import {MockExecutor} from "./mock/MockExecutor.sol";
import {MockValidator} from "./mock/MockValidator.sol";
import {MockHook} from "./mock/MockHook.sol";
import {MockPolicy} from "./mock/MockPolicy.sol";
import {MockSigner} from "./mock/MockSigner.sol";
import {MockERC721} from "./mock/MockERC721.sol";
import {MockERC1155} from "./mock/MockERC1155.sol";
import {IHook} from "src/interfaces/IERC7579Modules.sol";
import {CallType} from "src/types/Types.sol";
import "src/types/Constants.sol";
import "forge-std/console.sol";
import "src/types/Error.sol";
import "src/types/Events.sol";
import "src/types/Structs.sol";

contract MockCallee {
    uint256 public bar;
    string public data;

    event Lorem();

    error Haha();

    function foo() external {
        bar++;
        emit Lorem();
    }

    function lorem() external {
        data = "lorem ipsum";
    }

    function forceRevert() external {
        revert Haha();
    }
}

struct Call {
    address target;
    uint256 value;
    bytes data;
}

contract MockContractETH {
    function useTransfer(address payable recipient, uint256 v) external {
        recipient.transfer(v);
    }

    function useSend(address payable recipient, uint256 v) external {
        require(recipient.send(v), "send failed");
    }
}

contract KernelTest is Test {
    IEntryPoint ep;
    KernelFactory factory;
    MockValidator mockValidator;
    Kernel kernel;
    MockCallee callee;
    MockFallback mockFallback;
    address executor;
    address payable beneficiary;

    modifier unitTest() {
        vm.startPrank(address(ep));
        _;
        vm.stopPrank();
    }

    modifier unitTestExecutor() {
        vm.startPrank(address(executor));
        _;
        vm.stopPrank();
    }

    modifier entryPointTest() {
        _;
    }

    function setUp() external {
        ep = EntryPointLib.deploy();
        factory = new KernelFactory(ep);
        mockValidator = new MockValidator();
        callee = new MockCallee();
        executor = makeAddr("Executor");
        mockFallback = new MockFallback();
        beneficiary = payable(makeAddr("Beneficiary"));
        _initialize();
    }

    function _initialize() internal {
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({moduleType: 1, module: address(mockValidator), moduleData: hex"", internalData: hex""});
        kernel = factory.deploy(pkgs, 0);
        vm.deal(address(kernel), 1e18);

        vm.startPrank(address(ep));
        kernel.installModule(2, executor, abi.encode(hex"", ""));
        vm.stopPrank();
    }

    function encodeNonce(bool replayableUserOp, bool enableFlag, bool replayableEnable, bytes1 vType, bytes20 vId)
        internal
        returns (uint256 nonce)
    {
        uint8 uMode = 0;
        if (replayableEnable) {
            uMode += 2 ** 6;
        }
        if (enableFlag) {
            uMode += 2 ** 3;
        }
        if (replayableEnable) {
            uMode += 2 ** 2;
        }
        uint192 key = uint192(bytes24(abi.encodePacked(uMode, vType, vId, bytes2(0x00))));
        return ep.getNonce(address(kernel), key);
    }

    function test_codesize() external {
        address implementation = address(factory.template());
        require(implementation.code.length <= 24576, "Code too big");
        console.log("Code size :", implementation.code.length);
    }

    function test_receive_eth() external {
        address sender = makeAddr("Sender");
        address payable k = payable(address(kernel));
        vm.deal(sender, 1e18);
        // if not through kernel, only <address>call{value} works
        vm.startPrank(sender);
        vm.expectEmit(k);
        emit Received(sender, uint256(1));
        (bool success, ) = k.call{value: 1}(hex"");
        require(success);
        vm.stopPrank();

        MockContractETH mock = new MockContractETH();
        vm.deal(address(mock), 1e18);
        // if done through kernel, accepts both transfer and send
        vm.startPrank(address(ep));
        vm.expectEmit(k);
        emit Received(address(mock), uint256(1));
        kernel.execute(bytes32(0), abi.encodePacked(address(mock), uint256(0), abi.encodeWithSelector(MockContractETH.useTransfer.selector, k, uint256(1))));
        vm.expectEmit(k);
        emit Received(address(mock), uint256(1));
        kernel.execute(bytes32(0), abi.encodePacked(address(mock), uint256(0), abi.encodeWithSelector(MockContractETH.useSend.selector, k, uint256(1))));
        vm.stopPrank();
    }

    function test_receive_erc721() external {
        MockERC721 mock = new MockERC721();
        address sender = makeAddr("Sender");

        mock.mint(sender, 1);

        vm.prank(sender);
        mock.safeTransferFrom(sender, address(kernel), 1);

        mock.safeMint(address(kernel), 2);
    }

    function test_receive_erc1155() external {
        MockERC1155 mock = new MockERC1155();
        address sender = makeAddr("Sender");

        mock.mint(sender, 1, 1, hex"deadbeef");
        vm.prank(sender);
        mock.safeTransferFrom(sender, address(kernel), 1, 1, hex"deadbeef");
        
        mock.mint(address(kernel), 1, 1, hex"deadbeef");
        
        mock.mint(sender, 2, 4, hex"deadbeef");
        mock.mint(sender, 3, 5, hex"deadbeef");
        uint256[] memory ids = new uint256[](2);
        ids[0] = 2;
        ids[1] = 3;

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 2;
        amounts[1] = 3;
        vm.prank(sender);
        mock.safeBatchTransferFrom(sender, address(kernel), ids, amounts, hex"deadbeef");

        mock.batchMint(address(kernel), ids, amounts, hex"deadbeef");
    }

    function test_userop_root() external entryPointTest {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, false, false, bytes1(0), bytes20(0)),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector, bytes32(0), abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))), // TODO make this dynamic
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        mockValidator.sudoSetSuccess(true);
        ep.handleOps(ops, beneficiary);
        assertEq(callee.bar(), 1);
    }

    function test_userop_root_aa24_validation_failed() external entryPointTest {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, false, false, bytes1(0x00), bytes20(0)),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector, bytes32(0), abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))), // TODO make this dynamic
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        mockValidator.sudoSetSuccess(false);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        ep.handleOps(ops, beneficiary);
    }

    function test_userop_validator_aa24_notinstalled() external entryPointTest {
        MockValidator newValidator = new MockValidator();
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, false, false, bytes1(0x01), bytes20(address(newValidator))),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector, bytes32(0), abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))), // TODO make this dynamic
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        mockValidator.sudoSetSuccess(false);
        newValidator.sudoSetSuccess(true);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        ep.handleOps(ops, beneficiary);
    }

    function test_userop_validator_use_root_if_notinstalled() external entryPointTest {
        MockValidator newValidator = new MockValidator();
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, false, false, bytes1(0x01), bytes20(address(newValidator))),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector, bytes32(0), abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))), // TODO make this dynamic
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        mockValidator.sudoSetSuccess(true);
        newValidator.sudoSetSuccess(false);
        ep.handleOps(ops, beneficiary);
        assertEq(callee.bar(), 1);
    }

    function test_userop_validator_enable() external entryPointTest {
        MockValidator newValidator = new MockValidator();
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, true, false, bytes1(0x01), bytes20(address(newValidator))),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector, bytes32(0), abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))), // TODO make this dynamic
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });

        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(newValidator), moduleData: hex"", internalData: hex""});

        bytes memory sig = abi.encode(packages, hex"", hex"");

        ops[0].signature = sig;
        mockValidator.sudoSetSuccess(false);
        mockValidator.sudoSetValidSig(hex"");
        newValidator.sudoSetSuccess(true);
        ep.handleOps(ops, beneficiary);
        assertEq(callee.bar(), 1);
    }

    function test_userop_validator_aa23_enable_fail_wrong_signature() external entryPointTest {
        MockValidator newValidator = new MockValidator();
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, true, false, bytes1(0x01), bytes20(address(newValidator))),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector, bytes32(0), abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))), // TODO make this dynamic
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });

        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(newValidator), moduleData: hex"", internalData: hex""});

        bytes memory sig = abi.encode(packages, hex"", hex"");

        ops[0].signature = sig;
        mockValidator.sudoSetSuccess(false);
        newValidator.sudoSetSuccess(true);
        newValidator.sudoSetValidSig(hex"");
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSelector(InvalidEnableSignature.selector)
            )
        );
        ep.handleOps(ops, beneficiary);
    }

    function test_userop_validator_aa24_validation_failed() external entryPointTest {
        MockValidator newValidator = new MockValidator();
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, true, false, bytes1(0x01), bytes20(address(newValidator))),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector, bytes32(0), abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))), // TODO make this dynamic
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });

        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(newValidator), moduleData: hex"", internalData: hex""});

        bytes memory sig = abi.encode(packages, hex"", hex"");

        ops[0].signature = sig;
        mockValidator.sudoSetSuccess(false);
        newValidator.sudoSetSuccess(false);
        mockValidator.sudoSetValidSig(hex"");
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        ep.handleOps(ops, beneficiary);
    }

    function test_userop_permission_aa24_notinstalled() external entryPointTest {
        MockPolicy policy = new MockPolicy();
        MockSigner signer = new MockSigner();
        bytes20 permissionId = bytes20(keccak256(abi.encodePacked("Hello world")));
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, false, false, bytes1(0x02), permissionId),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector, bytes32(0), abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))), // TODO make this dynamic
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        mockValidator.sudoSetSuccess(false);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        ep.handleOps(ops, beneficiary);
    }

    function test_userop_permission_use_root_if_notinstalled() external entryPointTest {
        MockPolicy policy = new MockPolicy();
        MockSigner signer = new MockSigner();
        bytes20 permissionId = bytes20(keccak256(abi.encodePacked("Hello world")));
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, false, false, bytes1(0x02), permissionId),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector, bytes32(0), abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))), // TODO make this dynamic
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        mockValidator.sudoSetSuccess(true);
        ep.handleOps(ops, beneficiary);
        assertEq(callee.bar(), 1);
    }

    function test_userop_permission_enable() external entryPointTest {
        MockPolicy policy = new MockPolicy();
        MockSigner signer = new MockSigner();
        bytes20 permissionId = bytes20(keccak256(abi.encodePacked("Hello world")));
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, true, false, bytes1(0x02), permissionId),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector, bytes32(0), abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))), // TODO make this dynamic
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });

        Install[] memory packages = new Install[](2);
        packages[0] = Install({
            moduleType: 5,
            module: address(policy),
            moduleData: hex"",
            internalData: abi.encodePacked(permissionId)
        });
        packages[1] = Install({
            moduleType: 6,
            module: address(signer),
            moduleData: hex"",
            internalData: abi.encodePacked(permissionId)
        });

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = hex"";
        signatures[1] = hex"";

        bytes memory sig = abi.encode(packages, hex"", abi.encode(signatures));

        ops[0].signature = sig;
        mockValidator.sudoSetSuccess(false);
        mockValidator.sudoSetValidSig(hex"");

        policy.sudoSetValidSig(address(kernel), bytes32(abi.encodePacked(permissionId)), hex"");
        signer.sudoSetValidSig(address(kernel), bytes32(abi.encodePacked(permissionId)), hex"");
        ep.handleOps(ops, beneficiary);
        assertEq(callee.bar(), 1);
    }

    function test_userop_permission_aa23_enable_fail_wrong_signature() external entryPointTest {
        MockPolicy policy = new MockPolicy();
        MockSigner signer = new MockSigner();
        bytes20 permissionId = bytes20(keccak256(abi.encodePacked("Hello world")));
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, true, false, bytes1(0x02), permissionId),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector, bytes32(0), abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))), // TODO make this dynamic
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });

        Install[] memory packages = new Install[](2);
        packages[0] = Install({
            moduleType: 5,
            module: address(policy),
            moduleData: hex"",
            internalData: abi.encodePacked(permissionId)
        });
        packages[1] = Install({
            moduleType: 6,
            module: address(signer),
            moduleData: hex"",
            internalData: abi.encodePacked(permissionId)
        });

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = hex"";
        signatures[1] = hex"";

        bytes memory sig = abi.encode(packages, hex"", abi.encode(signatures));

        ops[0].signature = sig;
        mockValidator.sudoSetSuccess(false);
        policy.sudoSetValidSig(address(kernel), bytes32(abi.encodePacked(permissionId)), hex"");
        signer.sudoSetValidSig(address(kernel), bytes32(abi.encodePacked(permissionId)), hex"");
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSelector(InvalidEnableSignature.selector)
            )
        );
        ep.handleOps(ops, beneficiary);
    }

    function test_userop_permission_aa23_policy_failed() external entryPointTest {
        MockPolicy policy = new MockPolicy();
        MockSigner signer = new MockSigner();
        bytes20 permissionId = bytes20(keccak256(abi.encodePacked("Hello world")));
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, true, false, bytes1(0x02), permissionId),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector, bytes32(0), abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))), // TODO make this dynamic
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });

        Install[] memory packages = new Install[](2);
        packages[0] = Install({
            moduleType: 5,
            module: address(policy),
            moduleData: hex"",
            internalData: abi.encodePacked(permissionId)
        });
        packages[1] = Install({
            moduleType: 6,
            module: address(signer),
            moduleData: hex"",
            internalData: abi.encodePacked(permissionId)
        });

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = hex"";
        signatures[1] = hex"";

        bytes memory sig = abi.encode(packages, hex"", abi.encode(signatures));

        ops[0].signature = sig;
        mockValidator.sudoSetSuccess(false);
        mockValidator.sudoSetValidSig(hex"");
        policy.sudoSetValidSig(address(kernel), bytes32(abi.encodePacked(permissionId)), hex"deadbeef");
        signer.sudoSetValidSig(address(kernel), bytes32(abi.encodePacked(permissionId)), hex"");
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        ep.handleOps(ops, beneficiary);
    }

    function test_userop_permission_aa24_signer_validation_failed() external entryPointTest {
        MockPolicy policy = new MockPolicy();
        MockSigner signer = new MockSigner();
        bytes20 permissionId = bytes20(keccak256(abi.encodePacked("Hello world")));
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, true, false, bytes1(0x02), permissionId),
            initCode: hex"",
            callData: abi.encodeWithSelector(
                Kernel.execute.selector, bytes32(0), abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))), // TODO make this dynamic
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });

        Install[] memory packages = new Install[](2);
        packages[0] = Install({
            moduleType: 5,
            module: address(policy),
            moduleData: hex"",
            internalData: abi.encodePacked(permissionId)
        });
        packages[1] = Install({
            moduleType: 6,
            module: address(signer),
            moduleData: hex"",
            internalData: abi.encodePacked(permissionId)
        });

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = hex"";
        signatures[1] = hex"";

        bytes memory sig = abi.encode(packages, hex"", abi.encode(signatures));

        ops[0].signature = sig;
        mockValidator.sudoSetSuccess(false);
        mockValidator.sudoSetValidSig(hex"");
        policy.sudoSetValidSig(address(kernel), bytes32(abi.encodePacked(permissionId)), hex"");
        signer.sudoSetValidSig(address(kernel), bytes32(abi.encodePacked(permissionId)), hex"deadbeef");
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        ep.handleOps(ops, beneficiary);
    }

    function test_deploy() external unitTest {
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({moduleType: 1, module: address(mockValidator), moduleData: hex"", internalData: hex""});
        Kernel k = factory.deploy(pkgs, 1);
    }

    function test_install_executor_oninstall_success() external unitTest {
        address newEx = address(new MockExecutor());
        kernel.installModule(2, newEx, abi.encode(hex"deadbeef", ""));
        assertEq(address(kernel.executorConfig(newEx).hook), address(1));
    }

    function test_install_executor_oninstall_fail() external unitTest {
        address newEx = makeAddr("New Executor");
        kernel.installModule(2, newEx, abi.encode(hex"", ""));
        assertEq(address(kernel.executorConfig(newEx).hook), address(1));
    }

    function test_uninstall_executor_onuninstall_success() external unitTest {
        address newEx = address(new MockExecutor());
        kernel.installModule(2, newEx, abi.encode(hex"deadbeef", ""));
        assertEq(address(kernel.executorConfig(newEx).hook), address(1));
        kernel.uninstallModule(2, newEx, abi.encode(hex"", hex""));
        assertEq(address(kernel.executorConfig(newEx).hook), address(0));
    }

    function test_uninstall_executor_onuninstall_fail() external unitTest {
        address newEx = makeAddr("New Executor");
        kernel.installModule(2, newEx, abi.encode(hex"", ""));
        assertEq(address(kernel.executorConfig(newEx).hook), address(1));
        kernel.uninstallModule(2, newEx, abi.encode(hex"", hex""));
        assertEq(address(kernel.executorConfig(newEx).hook), address(0));
    }

    function test_install_hook() external unitTest {
        MockHook mockHook = new MockHook();
        kernel.installModule(4, address(mockHook), abi.encode(hex"", ""));
    }

    function test_uninstall_hook() external unitTest {
        MockHook mockHook = new MockHook();
        kernel.installModule(4, address(mockHook), abi.encode(hex"", ""));
        kernel.uninstallModule(4, address(mockHook), abi.encode(hex"", ""));
    }

    function test_install_validator() external unitTest {
        MockValidator newValidator = new MockValidator();
        ValidationId vId = ValidationId.wrap(bytes20(address(newValidator)));
        kernel.installModule(1, address(newValidator), abi.encode(hex"deadbeef", "InternalData"));
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.vType == VALIDATION_TYPE_VALIDATOR);
    }

    function test_uninstall_validator() external unitTest {
        MockValidator newValidator = new MockValidator();
        ValidationId vId = ValidationId.wrap(bytes20(address(newValidator)));
        kernel.installModule(1, address(newValidator), abi.encode(hex"deadbeef", "InternalData"));
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.vType == VALIDATION_TYPE_VALIDATOR);
        kernel.uninstallModule(1, address(newValidator), abi.encode(hex"deadbeef", "InternalData"));
        vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.vType == VALIDATION_TYPE_ROOT);
    }

    function test_install_selector_call() external unitTest {
        kernel.installModule(
            3,
            address(mockFallback),
            abi.encode(
                hex"deadbeef", abi.encodePacked(MockFallback.fallbackFunction.selector, bytes1(0x00), address(1))
            )
        );
        vm.expectEmit(address(mockFallback));
        emit MockFallback.Foobar();
        uint256 res = MockFallback(address(kernel)).fallbackFunction(10);
        assertEq(res, 100);
        SelectorManager.SelectorConfig memory c = kernel.selectorConfig(MockFallback.fallbackFunction.selector);
        assertEq(address(c.target), address(mockFallback));
        assertEq(address(c.hook), address(1));
        assertTrue(c.callType == CallType.wrap(bytes1(0x00)));
    }

    function test_install_selector_call_withhook() external unitTest {
        MockHook mockHook = new MockHook();
        kernel.installModule(4, address(mockHook), abi.encode(hex"", ""));
        kernel.installModule(
            3,
            address(mockFallback),
            abi.encode(
                hex"deadbeef", abi.encodePacked(MockFallback.fallbackFunction.selector, bytes1(0x00), address(mockHook))
            )
        );
        vm.expectEmit(address(mockFallback));
        emit MockFallback.Foobar();
        uint256 res = MockFallback(address(kernel)).fallbackFunction(10);
        assertEq(res, 100);
        SelectorManager.SelectorConfig memory c = kernel.selectorConfig(MockFallback.fallbackFunction.selector);
        assertEq(address(c.target), address(mockFallback));
        assertEq(address(c.hook), address(mockHook));
        assertTrue(c.callType == CallType.wrap(bytes1(0x00)));
    }

    function test_uninstall_selector_call() external unitTest {
        kernel.installModule(
            3,
            address(mockFallback),
            abi.encode(
                hex"deadbeef", abi.encodePacked(MockFallback.fallbackFunction.selector, bytes1(0x00), address(1))
            )
        );
        vm.expectEmit(address(mockFallback));
        emit MockFallback.Foobar();
        uint256 res = MockFallback(address(kernel)).fallbackFunction(10);
        assertEq(res, 100);
        SelectorManager.SelectorConfig memory c = kernel.selectorConfig(MockFallback.fallbackFunction.selector);
        assertEq(address(c.target), address(mockFallback));
        assertEq(address(c.hook), address(1));
        assertTrue(c.callType == CallType.wrap(bytes1(0x00)));
        kernel.uninstallModule(
            3, address(mockFallback), abi.encode(hex"", abi.encodePacked(MockFallback.fallbackFunction.selector))
        );
        c = kernel.selectorConfig(MockFallback.fallbackFunction.selector);
        assertEq(address(c.target), address(0));
        assertEq(address(c.hook), address(0));
        assertTrue(c.callType == CallType.wrap(bytes1(0x00)));
    }

    function test_install_selector_call_fail() external unitTest {
        kernel.installModule(
            3,
            address(mockFallback),
            abi.encode(
                hex"deadbeef", abi.encodePacked(MockFallback.fallbackFunction.selector, bytes1(0x00), address(1))
            )
        );
        vm.expectRevert(MockFallback.Limit.selector, address(mockFallback));
        MockFallback(address(kernel)).fallbackFunction(100);
    }

    function test_install_selector_delegatecall() external unitTest {
        kernel.installModule(
            3,
            address(mockFallback),
            abi.encode(
                hex"deadbeef", abi.encodePacked(MockFallback.fallbackFunction.selector, bytes1(0xff), address(1))
            )
        );
        vm.expectEmit(address(kernel));
        emit MockFallback.Foobar();
        uint256 res = MockFallback(address(kernel)).fallbackFunction(10);
        assertEq(res, 100);
    }

    function test_install_selector_delegatecall_fail() external unitTest {
        kernel.installModule(
            3,
            address(mockFallback),
            abi.encode(
                hex"deadbeef", abi.encodePacked(MockFallback.fallbackFunction.selector, bytes1(0xff), address(1))
            )
        );
        vm.expectRevert(MockFallback.Limit.selector, address(kernel));
        MockFallback(address(kernel)).fallbackFunction(100);
    }

    function test_install_selector_invalid_selector() external unitTest {
        kernel.installModule(
            3,
            address(mockFallback),
            abi.encode(
                hex"deadbeef", abi.encodePacked(MockFallback.fallbackFunction.selector, bytes1(0xff), address(1))
            )
        );
        vm.expectRevert(InvalidSelector.selector, address(kernel));
        MockFallback(address(kernel)).getData();
    }

    function test_execute() external unitTest {
        vm.expectEmit(address(callee));
        emit MockCallee.Lorem();
        kernel.execute(
            bytes32(0), abi.encodePacked(address(callee), uint256(0), abi.encodeWithSelector(MockCallee.foo.selector))
        );
        assertEq(callee.bar(), 1);
    }

    function test_execute_fail() external unitTest {
        vm.expectRevert(MockCallee.Haha.selector);
        kernel.execute(
            bytes32(0),
            abi.encodePacked(address(callee), uint256(0), abi.encodeWithSelector(MockCallee.forceRevert.selector))
        );
    }

    function test_execute_fail_invalid_callType() external unitTest {
        vm.expectRevert(InvalidCallType.selector, address(kernel));
        kernel.execute(
            LibERC7579.encodeMode(bytes1(0x02), bytes1(0x01), bytes4(0), bytes22(0)),
            abi.encodePacked(address(callee), uint256(0), abi.encodeWithSelector(MockCallee.foo.selector))
        );
    }

    function test_execute_fail_invalid_execType() external unitTest {
        vm.expectRevert(InvalidExecType.selector, address(kernel));
        kernel.execute(
            LibERC7579.encodeMode(bytes1(0x00), bytes1(0x02), bytes4(0), bytes22(0)),
            abi.encodePacked(address(callee), uint256(0), abi.encodeWithSelector(MockCallee.foo.selector))
        );
    }

    function test_execute_fail_try() external unitTest {
        kernel.execute(
            LibERC7579.encodeMode(bytes1(0x00), bytes1(0x01), bytes4(0), bytes22(0)),
            abi.encodePacked(address(callee), uint256(0), abi.encodeWithSelector(MockCallee.forceRevert.selector))
        );
    }

    function test_execute_batch() external unitTest {
        Call[] memory calls = new Call[](2);
        calls[0] = Call({target: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.foo.selector)});
        calls[1] = Call({target: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.lorem.selector)});
        assertEq(callee.data(), "");
        vm.expectEmit(address(callee));
        emit MockCallee.Lorem();
        kernel.execute(LibERC7579.encodeMode(bytes1(0x01), bytes1(0x00), bytes4(0), bytes22(0)), abi.encode(calls));
        assertEq(callee.bar(), 1);
        assertEq(callee.data(), "lorem ipsum");
    }

    function test_execute_batch_fail() external unitTest {
        Call[] memory calls = new Call[](2);
        calls[0] = Call({target: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.foo.selector)});
        calls[1] =
            Call({target: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.forceRevert.selector)});
        assertEq(callee.data(), "");
        vm.expectRevert(MockCallee.Haha.selector);
        kernel.execute(LibERC7579.encodeMode(bytes1(0x01), bytes1(0x00), bytes4(0), bytes22(0)), abi.encode(calls));
    }

    function test_execute_batch_fail_try() external unitTest {
        Call[] memory calls = new Call[](2);
        calls[0] = Call({target: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.foo.selector)});
        calls[1] =
            Call({target: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.forceRevert.selector)});
        assertEq(callee.data(), "");
        kernel.execute(LibERC7579.encodeMode(bytes1(0x01), bytes1(0x01), bytes4(0), bytes22(0)), abi.encode(calls));
        assertEq(callee.bar(), 1);
    }

    function test_execute_delegatecall() external unitTest {
        vm.expectEmit(address(kernel));
        emit MockCallee.Lorem();
        kernel.execute(
            LibERC7579.encodeMode(bytes1(0xff), bytes1(0x00), bytes4(0), bytes22(0)),
            abi.encodePacked(address(callee), abi.encodeWithSelector(MockCallee.foo.selector))
        );
    }

    function test_execute_delegatecall_fail() external unitTest {
        vm.expectRevert(MockCallee.Haha.selector);
        kernel.execute(
            LibERC7579.encodeMode(bytes1(0xff), bytes1(0x00), bytes4(0), bytes22(0)),
            abi.encodePacked(address(callee), abi.encodeWithSelector(MockCallee.forceRevert.selector))
        );
    }

    function test_execute_delegatecall_fail_try() external unitTest {
        kernel.execute(
            LibERC7579.encodeMode(bytes1(0xff), bytes1(0x01), bytes4(0), bytes22(0)),
            abi.encodePacked(address(callee), abi.encodeWithSelector(MockCallee.forceRevert.selector))
        );
    }

    function test_execute_from_executor() external unitTestExecutor {
        vm.expectEmit(address(callee));
        emit MockCallee.Lorem();
        kernel.executeFromExecutor(
            bytes32(0), abi.encodePacked(address(callee), uint256(0), abi.encodeWithSelector(MockCallee.foo.selector))
        );
        assertEq(callee.bar(), 1);
    }

    function test_execute_batch_from_executor() external unitTestExecutor {
        Call[] memory calls = new Call[](2);
        calls[0] = Call({target: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.foo.selector)});
        calls[1] = Call({target: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.lorem.selector)});
        assertEq(callee.data(), "");
        vm.expectEmit(address(callee));
        emit MockCallee.Lorem();
        kernel.executeFromExecutor(
            LibERC7579.encodeMode(bytes1(0x01), bytes1(0x00), bytes4(0), bytes22(0)), abi.encode(calls)
        );
        assertEq(callee.bar(), 1);
        assertEq(callee.data(), "lorem ipsum");
    }

    function test_execute_delegatecall_from_executor() external unitTestExecutor {
        vm.expectEmit(address(kernel));
        emit MockCallee.Lorem();
        kernel.executeFromExecutor(
            LibERC7579.encodeMode(bytes1(0xff), bytes1(0x00), bytes4(0), bytes22(0)),
            abi.encodePacked(address(callee), abi.encodeWithSelector(MockCallee.foo.selector))
        );
    }
}
