pragma solidity ^0.8.0;

import {KernelTest} from "./Kernel.t.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Kernel7702} from "src/Kernel7702.sol";
import {Kernel} from "src/Kernel.sol";
import {Install} from "src/types/Structs.sol";
import {ValidationId} from "src/types/Types.sol";
import {ERC1271_MAGICVALUE} from "src/types/Constants.sol";
import {InvalidValidationType} from "src/types/Error.sol";
import {validatorToIdentifier} from "src/lib/Utils.sol";
import {IValidator} from "src/interfaces/IERC7579Modules.sol";

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

    function test_7702_raw_compact_signature(bytes32 hash) external {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        bytes32 vs = bytes32(uint256(s) | (uint256(v - 27) << 255));
        bytes memory signature = abi.encodePacked(r, vs);
        assertEq(signature.length, 64);
        assertEq(kernel.isValidSignature(hash, signature), ERC1271_MAGICVALUE);
    }

    function test_7702_structured_root_compact_signature(bytes32 hash) external {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        bytes32 vs = bytes32(uint256(s) | (uint256(v - 27) << 255));
        bytes memory signature = abi.encodePacked(bytes1(0x00), r, vs);
        assertEq(signature.length, 65);
        assertEq(kernel.isValidSignature(hash, signature), ERC1271_MAGICVALUE);
    }

    function test_7702_raw_signature_invalid() external {
        // Use a fixed hash to ensure deterministic signature bytes
        bytes32 hash = keccak256("test_invalid_signature");
        (, uint256 wrongKey) = makeAddrAndKey("WrongSigner");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, hash);
        vm.expectRevert(InvalidValidationType.selector);
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

    /// @notice Regression test for the "require root validation be installed" audit fix:
    ///         after promoting a custom validator to root, the account must still be
    ///         able to switch root back to bytes21(0) (the EIP-7702 default fallback)
    ///         and authenticate userOps with the EOA's plain ECDSA key.
    /// @dev `_setRoot` only enforces the installed-status check for non-zero ValidationIds;
    ///      the bytes21(0) path is exempt precisely because the EOA's own key has no
    ///      install step. This test exercises both the exemption and the post-switch
    ///      signing path end-to-end.
    function test_change_root_back_to_7702_default_validator() external unitTest {
        // 1. Promote a custom validator to root (exercises the install-before-setRoot
        //    ordering that the audit fix codified).
        Install[] memory packages = new Install[](1);
        packages[0] = Install({moduleType: 1, module: address(newValidator), internalData: hex"", moduleData: hex""});
        kernel.setRoot(packages, false, hex"");

        ValidationId customRoot = validatorToIdentifier(IValidator(address(newValidator)));
        assertEq(ValidationId.unwrap(kernel.root()), ValidationId.unwrap(customRoot), "custom validator should be root");

        // 2. Switch root back to bytes21(0) -> EIP-7702 fallback (the EOA itself).
        kernel.setRoot(ValidationId.wrap(bytes21(0)));
        assertEq(ValidationId.unwrap(kernel.root()), bytes21(0), "root should be cleared back to bytes21(0)");

        // 3. A userOp signed by the EOA's plain ECDSA key on the FALLBACK path
        //    (vType = 0x00, vId = bytes20(0)) must validate successfully.
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

        vm.stopPrank();
        vm.prank(address(ep));
        uint256 validationData = kernel.validateUserOp(op, opHash, 0);
        assertEq(validationData, 0, "EIP-7702 default ECDSA validator should accept owner signature");
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
}
