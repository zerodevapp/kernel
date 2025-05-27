pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {EntryPointLib} from "./utils/EntryPointLib.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Kernel} from "src/Kernel.sol";
import {KernelHelper} from "src/KernelHelper.sol";
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
    MockValidator newValidator;
    Kernel kernel;
    MockCallee callee;
    MockFallback mockFallback;
    address executor;
    address payable beneficiary;
    MockPolicy policy;
    MockSigner signer;
    bytes20 permissionId;
    uint256 permissionRevertIndex;
    KernelHelper helper;

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
        helper = new KernelHelper();
        mockValidator = new MockValidator();
        newValidator = new MockValidator();
        callee = new MockCallee();
        executor = makeAddr("Executor");
        mockFallback = new MockFallback();
        beneficiary = payable(makeAddr("Beneficiary"));
        policy = new MockPolicy();
        signer = new MockSigner();
        permissionId = bytes20(keccak256(abi.encodePacked("Hello world")));
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

    function _rootSignUserOp(PackedUserOperation memory op, bool success, bool replay)
        internal
        returns (bytes memory sig)
    {
        mockValidator.sudoSetSuccess(success);
        return hex"";
    }

    function _rootSignHash(bytes32 hash, bool success) internal returns (bytes memory sig) {
        if (success) {
            mockValidator.sudoSetValidSig(hex"");
        }
        return hex"";
    }

    function _validatorSignUserOp(PackedUserOperation memory op, bool success, bool replay)
        internal
        returns (bytes memory sig)
    {
        newValidator.sudoSetSuccess(success);
        return hex"";
    }

    function _validatorSignHash(bytes32 hash, bool success) internal returns (bytes memory sig) {
        if (success) {
            newValidator.sudoSetValidSig(hex"");
        }
        return hex"";
    }

    function _permissionSignUserOp(PackedUserOperation memory op, bool success, bool replay)
        internal
        returns (bytes memory sig)
    {
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = hex"dead";
        signatures[1] = hex"beef";
        if (success || permissionRevertIndex != 0) {
            policy.sudoSetValidSig(address(kernel), permissionId, hex"dead");
        }
        if (success || permissionRevertIndex != 1) {
            signer.sudoSetValidSig(address(kernel), permissionId, hex"beef");
        }

        return abi.encode(signatures);
    }

    function _permissionSignHash(bytes32 hash, bool success) internal returns (bytes memory sig) {
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = hex"dead";
        signatures[1] = hex"beef";
        policy.sudoSetPass(address(kernel), permissionId, true);
        signer.sudoSetPass(address(kernel), permissionId, true);

        return abi.encode(signatures);
    }

    function enableSig(
        uint256 nonce,
        bool enableSuccess,
        bool replayable,
        Install[] memory packages,
        function(bytes32, bool) internal returns(bytes memory) signEnable
    ) internal returns (bytes memory sig) {
        bytes32 digest = helper.installDigest(address(kernel), replayable, nonce, packages);
        return signEnable(digest, enableSuccess);
    }

    function encodeEnableValidatorSignature(
        uint256 nonce,
        bool enableSuccess,
        bool replayable,
        function(bytes32, bool) internal returns(bytes memory) signEnable,
        bytes memory userOpSig
    ) internal returns (bytes memory sig) {
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(newValidator), moduleData: hex"", internalData: hex""});
        sig = abi.encode(
            uint256(0), packages, enableSig(nonce, enableSuccess, replayable, packages, signEnable), userOpSig
        );
    }

    function encodeEnablePermissionSignature(
        uint256 nonce,
        bool enableSuccess,
        bool replayable,
        function(bytes32, bool) internal returns(bytes memory) signEnable,
        bytes memory userOpSig
    ) internal returns (bytes memory sig) {
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

        sig = abi.encode(
            uint256(0), packages, enableSig(nonce, enableSuccess, replayable, packages, signEnable), userOpSig
        );
    }

    function encodeNonce(bool replayableUserOp, bool enableFlag, bool replayableEnable, bytes1 vType, bytes20 vId)
        internal
        returns (uint256 nonce)
    {
        uint8 uMode = 0;
        if (replayableUserOp) {
            uMode += 2 ** 6;
        }
        if (enableFlag) {
            uMode += 2 ** 3;
        }
        if (replayableEnable) {
            uMode += 2 ** 2;
        }
        ValidationMode vMode = ValidationMode.wrap(bytes1(uMode));
        uint192 key = uint192(bytes24(abi.encodePacked(uMode, vType, vId, bytes2(0x00))));
        return ep.getNonce(address(kernel), key);
    }

    function test_codesize() external {
        vm.skip(true);
        address implementation = address(factory.template());
        console.log("Code size :", implementation.code.length);
        require(implementation.code.length <= 24576, "Code too big");
        console.log("space left :", 24576 - implementation.code.length);
    }

    function test_receive_eth() external {
        address sender = makeAddr("Sender");
        address payable k = payable(address(kernel));
        vm.deal(sender, 1e18);
        // if not through kernel, only <address>call{value} works
        vm.startPrank(sender);
        vm.expectEmit(k);
        emit Received(sender, uint256(1));
        (bool success,) = k.call{value: 1}(hex"");
        require(success);
        vm.stopPrank();

        MockContractETH mock = new MockContractETH();
        vm.deal(address(mock), 1e18);
        // if done through kernel, accepts both transfer and send
        vm.startPrank(address(ep));
        vm.expectEmit(k);
        emit Received(address(mock), uint256(1));
        kernel.execute(
            bytes32(0),
            abi.encodePacked(
                address(mock), uint256(0), abi.encodeWithSelector(MockContractETH.useTransfer.selector, k, uint256(1))
            )
        );
        vm.expectEmit(k);
        emit Received(address(mock), uint256(1));
        kernel.execute(
            bytes32(0),
            abi.encodePacked(
                address(mock), uint256(0), abi.encodeWithSelector(MockContractETH.useSend.selector, k, uint256(1))
            )
        );
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

    function test_executeuserop_root() external entryPointTest {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(false, false, false, bytes1(0), bytes20(0)),
            initCode: hex"",
            callData: abi.encodePacked(
                Kernel.executeUserOp.selector,
                abi.encodeWithSelector(
                    Kernel.execute.selector,
                    bytes32(0),
                    abi.encodePacked(address(callee), uint256(0), MockCallee.foo.selector)
                )
            ),
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))), // TODO make this dynamic
            preVerificationGas: 1000000,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: hex"",
            signature: hex""
        });
        ops[0].signature = _rootSignUserOp(ops[0], true, false);
        vm.startPrank(address(ep));
        kernel.executeUserOp(ops[0], keccak256("hello world"));
        vm.stopPrank();
        assertEq(callee.bar(), 1);
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
        ops[0].signature = _rootSignUserOp(ops[0], true, false);
        ep.handleOps(ops, beneficiary);
        assertEq(callee.bar(), 1);
    }

    function test_userop_root_replayable() external entryPointTest {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = PackedUserOperation({
            sender: address(kernel),
            nonce: encodeNonce(true, false, false, bytes1(0), bytes20(0)),
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
        ops[0].signature = _rootSignUserOp(ops[0], true, true);
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
        ops[0].signature = _rootSignUserOp(ops[0], false, false);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        ep.handleOps(ops, beneficiary);
    }

    function test_userop_validator_aa24_notinstalled() external entryPointTest {
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
        ops[0].signature = _validatorSignUserOp(ops[0], true, false);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        ep.handleOps(ops, beneficiary);
    }

    function test_userop_validator_use_root_if_notinstalled() external entryPointTest {
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
        ops[0].signature = _rootSignUserOp(ops[0], true, false);
        ep.handleOps(ops, beneficiary);
        assertEq(callee.bar(), 1);
    }

    function test_userop_validator_enable() external entryPointTest {
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
        ops[0].signature =
            encodeEnableValidatorSignature(0, true, false, _rootSignHash, _validatorSignUserOp(ops[0], true, false));
        ep.handleOps(ops, beneficiary);
        assertEq(callee.bar(), 1);
    }

    function test_userop_validator_aa24_enable_fail_wrong_signature() external entryPointTest {
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
        ops[0].signature =
            encodeEnableValidatorSignature(0, false, false, _rootSignHash, _validatorSignUserOp(ops[0], true, false));
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        ep.handleOps(ops, beneficiary);
    }

    function test_userop_validator_aa24_validation_failed() external entryPointTest {
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

        ops[0].signature =
            encodeEnableValidatorSignature(0, true, false, _rootSignHash, _validatorSignUserOp(ops[0], false, false));
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        ep.handleOps(ops, beneficiary);
    }

    function test_userop_permission_aa24_notinstalled() external entryPointTest {
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
        ops[0].signature = _permissionSignUserOp(ops[0], true, false);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        ep.handleOps(ops, beneficiary);
    }

    function test_userop_permission_use_root_if_notinstalled() external entryPointTest {
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
        ops[0].signature = _rootSignUserOp(ops[0], true, false);
        ep.handleOps(ops, beneficiary);
        assertEq(callee.bar(), 1);
    }

    function test_userop_permission_enable() external entryPointTest {
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

        ops[0].signature =
            encodeEnablePermissionSignature(0, true, false, _rootSignHash, _permissionSignUserOp(ops[0], true, false));
        ep.handleOps(ops, beneficiary);
        assertEq(callee.bar(), 1);
    }

    function test_userop_permission_aa24_enable_fail_wrong_signature() external entryPointTest {
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
        ops[0].signature =
            encodeEnablePermissionSignature(0, false, false, _rootSignHash, _permissionSignUserOp(ops[0], true, false));
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        ep.handleOps(ops, beneficiary);
    }

    function test_userop_permission_aa24_policy_failed() external entryPointTest {
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
        ops[0].signature =
            encodeEnablePermissionSignature(0, true, false, _rootSignHash, _permissionSignUserOp(ops[0], false, false));
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        ep.handleOps(ops, beneficiary);
    }

    function test_userop_permission_aa24_signer_validation_failed() external entryPointTest {
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
        permissionRevertIndex = 1;
        ops[0].signature =
            encodeEnablePermissionSignature(0, true, false, _rootSignHash, _permissionSignUserOp(ops[0], false, false));
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        ep.handleOps(ops, beneficiary);
    }

    function test_deploy() external unitTest {
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({moduleType: 1, module: address(mockValidator), moduleData: hex"", internalData: hex""});
        Kernel k = factory.deploy(pkgs, 1);
    }

    function test_deploy_existing() external {
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({moduleType: 1, module: address(mockValidator), moduleData: hex"", internalData: hex""});
        Kernel k = factory.deploy(pkgs, 1);
        assertEq(address(k), address(factory.deploy(pkgs, 1)));
    }
    
    function test_deploy_with_call() external unitTest {
        Install[] memory initPkgs = new Install[](1);
        initPkgs[0] = Install({moduleType: 1, module: address(mockValidator), moduleData: hex"", internalData: hex""});
        Install[] memory pkgs = new Install[](1);
        pkgs[0] = Install({moduleType: 1, module: address(newValidator), moduleData: hex"", internalData: hex""});
        bytes memory sig = enableSig(0, true, false, pkgs, _rootSignHash);
        Kernel k = factory.deployWithCall(initPkgs, 1, abi.encodeWithSelector(0xa706cd33, false, 0, pkgs, sig));
        ValidationInfo memory vInfo = k.validationInfo(ValidationId.wrap(bytes20(address(newValidator))));
        assertTrue(vInfo.vType == VALIDATION_TYPE_VALIDATOR);
    }

    function test_install_executor_oninstall_success() external unitTest {
        assertTrue(kernel.supportsModule(2));
        address newEx = address(new MockExecutor());
        kernel.installModule(2, newEx, abi.encode(hex"deadbeef", ""));
        assertEq(address(kernel.executorConfig(newEx).hook), address(1));
        assertTrue(kernel.isModuleInstalled(2, newEx, hex""));
    }

    function test_install_executor_oninstall_fail() external unitTest {
        address newEx = makeAddr("New Executor");
        kernel.installModule(2, newEx, abi.encode(hex"", ""));
        assertEq(address(kernel.executorConfig(newEx).hook), address(1));
        assertTrue(kernel.isModuleInstalled(2, newEx, hex""));
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

    function test_install_packages_with_signature() external unitTest {
        Install[] memory packages = new Install[](2);
        packages[0] = Install({moduleType: 1, module: address(newValidator), internalData: hex"", moduleData: hex""});
        packages[1] = Install({
            moduleType: 5,
            module: address(policy),
            internalData: abi.encodePacked(permissionId),
            moduleData: hex""
        });
        kernel.installModule(false, 0, packages, enableSig(0, true, false, packages, _rootSignHash));
    }

    function test_change_root() external unitTest {
        Install[] memory packages = new Install[](2);
        packages[0] = Install({moduleType: 1, module: address(newValidator), internalData: hex"", moduleData: hex""});
        packages[1] = Install({
            moduleType: 5,
            module: address(policy),
            internalData: abi.encodePacked(permissionId),
            moduleData: hex""
        });
        kernel.installModule(false, 0, packages, enableSig(0, true, false, packages, _rootSignHash));

        kernel.setRoot(ValidationId.wrap(bytes20(address(newValidator))));
    }

    function test_upgradeTo() external unitTest {
        Kernel newTemplate = new Kernel(ep);
        kernel.upgradeToAndCall(address(newTemplate), hex"");
        bytes32 impl = vm.load(address(kernel), ERC1967_IMPLEMENTATION_SLOT);
        assertEq(address(uint160(uint256(impl))), address(newTemplate));
    }

    function test_install_invalid() external unitTest {
        MockHook mockHook = new MockHook();
        vm.expectRevert(NotImplemented.selector);
        kernel.installModule(10, address(mockHook), abi.encode(hex"", ""));
    }

    function test_uninstall_invalid() external unitTest {
        MockHook mockHook = new MockHook();
        vm.expectRevert(NotImplemented.selector);
        kernel.uninstallModule(10, address(mockHook), abi.encode(hex"", ""));
    }

    function test_install_hook() external unitTest {
        assertTrue(kernel.supportsModule(4));
        MockHook mockHook = new MockHook();
        kernel.installModule(4, address(mockHook), abi.encode(hex"", ""));
        assertTrue(kernel.isModuleInstalled(4, address(mockHook), hex""));
    }

    function test_uninstall_hook() external unitTest {
        MockHook mockHook = new MockHook();
        kernel.installModule(4, address(mockHook), abi.encode(hex"", ""));
        kernel.uninstallModule(4, address(mockHook), abi.encode(hex"", ""));
    }

    function test_install_validator() external unitTest {
        assertTrue(kernel.supportsModule(1));
        ValidationId vId = ValidationId.wrap(bytes20(address(newValidator)));
        kernel.installModule(1, address(newValidator), abi.encode(hex"deadbeef", "InternalData"));
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.vType == VALIDATION_TYPE_VALIDATOR);
        bytes4 ret = kernel.isValidSignature(keccak256("Hello world"), abi.encodePacked(newValidator, _validatorSignHash(keccak256("Hello world"), true)));
        assertEq(ret, ERC1271_MAGICVALUE);
        assertTrue(kernel.isModuleInstalled(1, address(newValidator), hex""));
    }

    function test_uninstall_validator() external unitTest {
        ValidationId vId = ValidationId.wrap(bytes20(address(newValidator)));
        kernel.installModule(1, address(newValidator), abi.encode(hex"deadbeef", "InternalData"));
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.vType == VALIDATION_TYPE_VALIDATOR);
        kernel.uninstallModule(1, address(newValidator), abi.encode(hex"deadbeef", "InternalData"));
        vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.vType == VALIDATION_TYPE_ROOT);
    }

    function test_install_permission() external unitTest {
        assertTrue(kernel.supportsModule(5));
        assertTrue(kernel.supportsModule(6));
        ValidationId vId = ValidationId.wrap(permissionId);
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.vType == VALIDATION_TYPE_ROOT);
        kernel.installModule(5, address(policy), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        kernel.installModule(6, address(signer), abi.encode(hex"deadbeef", abi.encodePacked(permissionId)));
        bytes4 ret = kernel.isValidSignature(keccak256("Hello world"), abi.encodePacked(permissionId, _permissionSignHash(keccak256("Hello world"), true)));
        assertEq(ret, ERC1271_MAGICVALUE);
        assertTrue(kernel.isModuleInstalled(5, address(policy), abi.encodePacked(permissionId)));
        assertTrue(kernel.isModuleInstalled(6, address(signer), abi.encodePacked(permissionId)));
    }

    function test_install_policy() external unitTest {
        assertTrue(kernel.supportsModule(5));
        MockPolicy mock = new MockPolicy();
        ValidationId vId = ValidationId.wrap(permissionId);
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.vType == VALIDATION_TYPE_ROOT);
        kernel.installModule(5, address(mock), abi.encode(hex"deadbeef", abi.encodePacked(vId)));
        vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.vType == VALIDATION_TYPE_PERMISSION);
        assertTrue(kernel.isModuleInstalled(5, address(mock), abi.encodePacked(permissionId)));
    }

    function test_uninstall_policy() external unitTest {
        MockPolicy mock = new MockPolicy();
        ValidationId vId = ValidationId.wrap(permissionId);
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.vType == VALIDATION_TYPE_ROOT);
        kernel.installModule(5, address(mock), abi.encode(hex"deadbeef", abi.encodePacked(vId)));
        vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.vType == VALIDATION_TYPE_PERMISSION);
        kernel.uninstallModule(5, address(mock), abi.encode(hex"deadbeef", abi.encodePacked(vId)));
        vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.vType == VALIDATION_TYPE_ROOT);
    }

    function test_install_signer() external unitTest {
        assertTrue(kernel.supportsModule(6));
        MockSigner mock = new MockSigner();
        ValidationId vId = ValidationId.wrap(permissionId);
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.vType == VALIDATION_TYPE_ROOT);
        kernel.installModule(6, address(mock), abi.encode(hex"deadbeef", abi.encodePacked(vId)));
        vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.vType == VALIDATION_TYPE_PERMISSION);
        assertTrue(kernel.isModuleInstalled(6, address(mock), abi.encodePacked(permissionId)));
    }

    function test_uninstall_signer() external unitTest {
        MockSigner mock = new MockSigner();
        ValidationId vId = ValidationId.wrap(bytes20(keccak256(abi.encodePacked("deadbeef"))));
        ValidationInfo memory vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.vType == VALIDATION_TYPE_ROOT);
        kernel.installModule(6, address(mock), abi.encode(hex"deadbeef", abi.encodePacked(vId)));
        vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.vType == VALIDATION_TYPE_PERMISSION);
        assertTrue(vInfo.signer == address(mock));
        kernel.uninstallModule(6, address(mock), abi.encode(hex"deadbeef", abi.encodePacked(vId)));
        vInfo = kernel.validationInfo(vId);
        assertTrue(vInfo.vType == VALIDATION_TYPE_ROOT);
        assertTrue(vInfo.signer == address(0));
    }

    function test_install_selector_call() external unitTest {
        assertTrue(kernel.supportsModule(3));
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
        assertTrue(kernel.isModuleInstalled(3, address(mockFallback), abi.encodePacked(MockFallback.fallbackFunction.selector)));
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
        assertEq(kernel.supportsExecutionMode(bytes32(0)), true);
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
        bytes32 mode = LibERC7579.encodeMode(bytes1(0x02), bytes1(0x01), bytes4(0), bytes22(0));
        assertEq(kernel.supportsExecutionMode(mode), false);
        vm.expectRevert(InvalidCallType.selector, address(kernel));
        kernel.execute(
            mode,
            abi.encodePacked(address(callee), uint256(0), abi.encodeWithSelector(MockCallee.foo.selector))
        );
    }

    function test_execute_fail_invalid_execType() external unitTest {
        bytes32 mode = LibERC7579.encodeMode(bytes1(0x00), bytes1(0x02), bytes4(0), bytes22(0));
        assertEq(kernel.supportsExecutionMode(mode), false);
        vm.expectRevert(InvalidExecType.selector, address(kernel));
        kernel.execute(
            mode,
            abi.encodePacked(address(callee), uint256(0), abi.encodeWithSelector(MockCallee.foo.selector))
        );
    }

    function test_execute_fail_try() external unitTest {
        bytes32 mode = LibERC7579.encodeMode(bytes1(0x00), bytes1(0x01), bytes4(0), bytes22(0));
        assertEq(kernel.supportsExecutionMode(mode), true);
        kernel.execute(
            mode,
            abi.encodePacked(address(callee), uint256(0), abi.encodeWithSelector(MockCallee.forceRevert.selector))
        );
    }

    function test_execute_batch() external unitTest {
        Call[] memory calls = new Call[](2);
        calls[0] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.foo.selector)});
        calls[1] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.lorem.selector)});
        assertEq(callee.data(), "");
        bytes32 mode = LibERC7579.encodeMode(bytes1(0x01), bytes1(0x00), bytes4(0), bytes22(0));
        assertEq(kernel.supportsExecutionMode(mode), true);
        vm.expectEmit(address(callee));
        emit MockCallee.Lorem();
        kernel.execute(mode, abi.encode(calls));
        assertEq(callee.bar(), 1);
        assertEq(callee.data(), "lorem ipsum");
    }

    function test_execute_batch_fail() external unitTest {
        Call[] memory calls = new Call[](2);
        calls[0] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.foo.selector)});
        calls[1] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.forceRevert.selector)});
        assertEq(callee.data(), "");
        bytes32 mode = LibERC7579.encodeMode(bytes1(0x01), bytes1(0x00), bytes4(0), bytes22(0));
        assertEq(kernel.supportsExecutionMode(mode), true);
        vm.expectRevert(MockCallee.Haha.selector);
        kernel.execute(LibERC7579.encodeMode(bytes1(0x01), bytes1(0x00), bytes4(0), bytes22(0)), abi.encode(calls));
    }

    function test_execute_batch_fail_try() external unitTest {
        Call[] memory calls = new Call[](2);
        calls[0] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.foo.selector)});
        calls[1] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.forceRevert.selector)});
        assertEq(callee.data(), "");
        bytes32 mode = LibERC7579.encodeMode(bytes1(0x01), bytes1(0x01), bytes4(0), bytes22(0));
        assertEq(kernel.supportsExecutionMode(mode), true);
        kernel.execute(LibERC7579.encodeMode(bytes1(0x01), bytes1(0x01), bytes4(0), bytes22(0)), abi.encode(calls));
        assertEq(callee.bar(), 1);
    }

    function test_execute_delegatecall() external unitTest {
        bytes32 mode = LibERC7579.encodeMode(bytes1(0xff), bytes1(0x00), bytes4(0), bytes22(0));
        assertEq(kernel.supportsExecutionMode(mode), true);
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
        bytes32 mode = LibERC7579.encodeMode(bytes1(0xff), bytes1(0x01), bytes4(0), bytes22(0));
        assertEq(kernel.supportsExecutionMode(mode), true);
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
        calls[0] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.foo.selector)});
        calls[1] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.lorem.selector)});
        assertEq(callee.data(), "");
        vm.expectEmit(address(callee));
        emit MockCallee.Lorem();
        kernel.executeFromExecutor(
            LibERC7579.encodeMode(bytes1(0x01), bytes1(0x00), bytes4(0), bytes22(0)), abi.encode(calls)
        );
        assertEq(callee.bar(), 1);
        assertEq(callee.data(), "lorem ipsum");
    }

    bytes32 constant MODE_EXECUTE_WITH_OP_DATA = bytes10(0x01000000000078210001);

    function encodeInstallWithExecute(Call[] memory calls, bool replayable, uint256 nonce, Install[] memory packages)
        internal
        returns (bytes memory sig)
    {
        InstallAndExecute memory ie =
            InstallAndExecute({replayable: replayable, nonce: nonce, packages: packages, signature: hex""});
        bytes32 hash = helper.installAndExecuteDigest(address(kernel), MODE_EXECUTE_WITH_OP_DATA, calls, ie);
        sig = abi.encode(false, uint256(0), packages, _rootSignHash(hash, true));
    }

    function test_execute_batch_from_executor_with_install_data() external {
        address newExecutor = makeAddr("New Executor");
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 2, module: newExecutor, internalData: hex"", moduleData: hex""});

        Call[] memory calls = new Call[](2);
        calls[0] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.foo.selector)});
        calls[1] = Call({to: address(callee), value: 0, data: abi.encodeWithSelector(MockCallee.lorem.selector)});
        assertEq(callee.data(), "");
        vm.startPrank(newExecutor);
        bytes memory installData = encodeInstallWithExecute(calls, false, uint256(0), packages);
        vm.expectEmit(address(callee));
        emit MockCallee.Lorem();
        kernel.executeFromExecutor(MODE_EXECUTE_WITH_OP_DATA, abi.encode(calls, installData));
        assertEq(callee.bar(), 1);
        assertEq(callee.data(), "lorem ipsum");
        vm.stopPrank();
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
