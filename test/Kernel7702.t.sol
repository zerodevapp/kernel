pragma solidity ^0.8.0;

import {KernelTest} from "./Kernel.t.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Kernel7702} from "src/Kernel7702.sol";
import {Kernel} from "src/Kernel.sol";
import {Install} from "src/types/Structs.sol";
import {ValidationId} from "src/types/Types.sol";
import {ERC1271_MAGICVALUE} from "src/types/Constants.sol";
import {ERC1271_INVALID} from "src/types/Constants.sol";
import {InvalidValidationType} from "src/types/Error.sol";

contract Kernel7702Harness is Kernel7702 {
    constructor(IEntryPoint _ep) Kernel7702(_ep) {}

    function exposed_verifyStatelessSignature(
        Install[] calldata packages,
        ValidationId vId,
        bytes32 hash,
        bytes calldata signature
    ) external view returns (bool) {
        return _verifyStatelessSignature(packages, vId, hash, signature);
    }
}

contract Kernel7702Test is KernelTest {
    address owner;
    uint256 ownerKey;

    Kernel7702 template;

    function _initialize() internal override {
        template = new Kernel7702(ep);
        is7702 = true;
        (owner, ownerKey) = makeAddrAndKey("Owner");
        kernel = Kernel(payable(owner));
        vm.etch(owner, abi.encodePacked(bytes3(0xef0100), address(template)));
        vm.deal(owner, 1e18);

        vm.startPrank(address(ep));
        kernel.installModule(2, executor, abi.encode(hex"", hex""));
        vm.stopPrank();
    }

    function _rootSignUserOp(PackedUserOperation memory op, bool success, bool replay)
        internal
        view
        override
        returns (bytes memory sig)
    {
        bytes32 hash = replay ? hashHelper.chainAgnosticUserOpHash(address(ep), op) : ep.getUserOpHash(op);
        return _rootSignHash(hash, success);
    }

    function _rootSignHash(bytes32 hash, bool success) internal view override returns (bytes memory sig) {
        if (!success) {
            hash = keccak256(abi.encodePacked(hash));
        }
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        return abi.encodePacked(r, s, v);
    }

    function test_7702_unwrapped_erc1271(bytes32 hash) external erc1271Test {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        (bytes4 ret) = kernel.isValidSignature(hash, abi.encodePacked(r, s, v));
        assertEq(ret, ERC1271_MAGICVALUE);
    }

    function test_7702_unwrapped_erc1271_offchain(bytes32 hash) external view {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        (bytes4 ret) = kernel.isValidSignature(hash, abi.encodePacked(r, s, v));
        assertEq(ret, ERC1271_MAGICVALUE);
    }

    function test_7702_raw_signature_valid(bytes32 hash) external {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        (bytes4 ret) = kernel.isValidSignature(hash, abi.encodePacked(r, s, v));
        assertEq(ret, ERC1271_MAGICVALUE);
    }

    function test_7702_raw_signature_invalid() external {
        // Use a fixed hash to ensure deterministic signature bytes
        bytes32 hash = keccak256("test_invalid_signature");
        (, uint256 wrongKey) = makeAddrAndKey("WrongSigner");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, hash);
        // When raw signature verification fails, the code falls through to validation mode parsing
        // which reverts because a raw signature doesn't have valid validation type bytes
        vm.expectRevert();
        kernel.isValidSignature(hash, abi.encodePacked(r, s, v));
    }

    function test_change_root_check_vId_0() external unitTest {
        Install[] memory packages = new Install[](3);
        packages[0] = Install({moduleType: 1, module: address(newValidator), internalData: hex"", moduleData: hex""});
        packages[1] = Install({
            moduleType: 5, module: address(policy), internalData: abi.encodePacked(permissionId), moduleData: hex""
        });
        packages[2] = Install({
            moduleType: 6, module: address(signer), internalData: abi.encodePacked(permissionId), moduleData: hex""
        });

        kernel.setRoot(packages, false, hex"");

        kernel.setRoot(ValidationId.wrap(bytes20(0)));
    }

    // ===== Kernel7702.initialize() is a NO-OP =====

    function test_7702_initialize_is_noop() external {
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(newValidator), moduleData: hex"", internalData: hex""});
        kernel.initialize(packages);
        // Nothing should be installed since initialize is a no-op
        assertFalse(kernel.isModuleInstalled(1, address(newValidator), ""));
    }

    function test_7702_initialize_empty_packages() external {
        Install[] memory packages = new Install[](0);
        kernel.initialize(packages);
    }

    function test_7702_initialize_callable_multiple_times() external {
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(newValidator), moduleData: hex"", internalData: hex""});
        kernel.initialize(packages);
        kernel.initialize(packages);
        assertFalse(kernel.isModuleInstalled(1, address(newValidator), ""));
    }

    // ===== _verifyFallbackSignature via validateUserOp (root = bytes21(0) path) =====

    function test_7702_fallback_sig_valid_returns_success() external {
        PackedUserOperation memory op;
        op.sender = address(kernel);
        op.nonce = encodeNonce(false, false, false, bytes1(0), bytes20(0));
        op.callData = abi.encodeWithSelector(kernel.execute.selector, bytes32(0), "");
        op.accountGasLimits = bytes32(uint256(100000) << 128 | uint256(100000));
        op.preVerificationGas = 100000;
        op.gasFees = bytes32(uint256(1) << 128 | uint256(1));

        bytes32 opHash = ep.getUserOpHash(op);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, opHash);
        op.signature = abi.encodePacked(r, s, v);

        vm.prank(address(ep));
        uint256 validationData = kernel.validateUserOp(op, opHash, 0);
        assertEq(validationData, 0);
    }

    function test_7702_fallback_sig_invalid_returns_failure() external {
        PackedUserOperation memory op;
        op.sender = address(kernel);
        op.nonce = encodeNonce(false, false, false, bytes1(0), bytes20(0));
        op.callData = abi.encodeWithSelector(kernel.execute.selector, bytes32(0), "");
        op.accountGasLimits = bytes32(uint256(100000) << 128 | uint256(100000));
        op.preVerificationGas = 100000;
        op.gasFees = bytes32(uint256(1) << 128 | uint256(1));

        bytes32 opHash = ep.getUserOpHash(op);
        (, uint256 wrongKey) = makeAddrAndKey("WrongSigner");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, opHash);
        op.signature = abi.encodePacked(r, s, v);

        vm.prank(address(ep));
        uint256 validationData = kernel.validateUserOp(op, opHash, 0);
        assertEq(validationData, 1);
    }

    function test_7702_fallback_sig_malformed_returns_failure() external {
        PackedUserOperation memory op;
        op.sender = address(kernel);
        op.nonce = encodeNonce(false, false, false, bytes1(0), bytes20(0));
        op.callData = abi.encodeWithSelector(kernel.execute.selector, bytes32(0), "");
        op.accountGasLimits = bytes32(uint256(100000) << 128 | uint256(100000));
        op.preVerificationGas = 100000;
        op.gasFees = bytes32(uint256(1) << 128 | uint256(1));

        bytes32 opHash = ep.getUserOpHash(op);
        op.signature = hex"deadbeef"; // malformed signature

        vm.prank(address(ep));
        uint256 validationData = kernel.validateUserOp(op, opHash, 0);
        assertEq(validationData, 1);
    }

    // ===== _verifyStatelessSignature: InvalidValidationType route =====

    function test_7702_verifyStatelessSignature_revert_invalidValidationType() external {
        Kernel7702Harness harness = new Kernel7702Harness(ep);
        Install[] memory packages = new Install[](0);
        // ValidationId with ROOT type (0x00) is neither VALIDATOR nor PERMISSION
        vm.expectRevert(InvalidValidationType.selector);
        harness.exposed_verifyStatelessSignature(packages, ValidationId.wrap(bytes21(0)), bytes32(0), hex"");
    }
}
