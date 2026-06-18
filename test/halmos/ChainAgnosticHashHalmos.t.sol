// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Lib4337} from "src/lib/Lib4337.sol";

/// @dev Minimal stand-in for an EntryPoint that satisfies the IERC5267 view used by
/// Lib4337._hashTypedDataSansChainId. Returns constants (independent of block.chainid)
/// so the harness can vary the chain id between calls without changing the EP's reply.
contract MockEip712EntryPoint {
    function eip712Domain()
        external
        pure
        returns (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        )
    {
        fields = bytes1(0x0f);
        name = "ERC4337";
        version = "1";
        chainId = 0; // intentionally fixed: the domain hash that Lib4337 builds drops chainId entirely.
        verifyingContract = address(0);
        salt = bytes32(0);
        extensions = new uint256[](0);
    }
}

/// @dev External wrapper so we can call Lib4337.chainAgnosticUserOpHash (which requires
/// `calldata`) starting from a memory-built PackedUserOperation inside check_ functions.
contract HashWrapper {
    function hashOf(address ep, PackedUserOperation calldata op) external view returns (bytes32) {
        return Lib4337.chainAgnosticUserOpHash(ep, op);
    }
}

/// @notice Halmos properties for Lib4337.chainAgnosticUserOpHash:
///   1. determinism (same inputs → same hash)
///   2. chain-id independence (changing block.chainid does not change the hash)
///   3. field-sensitivity (sender / nonce / callData / accountGasLimits flips change the hash)
contract ChainAgnosticHashHalmos is SymTest, Test {
    HashWrapper wrapper;
    address ep;

    // Halmos symbolic-byte length bound. Keep small to stay tractable; the property holds
    // structurally, not by length, so a tight bound is sufficient.
    uint256 internal constant BYTES_LEN = 4;

    function setUp() external {
        wrapper = new HashWrapper();
        ep = address(new MockEip712EntryPoint());
    }

    // ---------- helpers ----------

    function _symOp(string memory tag) internal returns (PackedUserOperation memory op) {
        op.sender = svm.createAddress(string.concat(tag, ".sender"));
        op.nonce = svm.createUint256(string.concat(tag, ".nonce"));
        op.initCode = svm.createBytes(BYTES_LEN, string.concat(tag, ".initCode"));
        op.callData = svm.createBytes(BYTES_LEN, string.concat(tag, ".callData"));
        op.accountGasLimits = svm.createBytes32(string.concat(tag, ".accountGasLimits"));
        op.preVerificationGas = svm.createUint256(string.concat(tag, ".preVerificationGas"));
        op.gasFees = svm.createBytes32(string.concat(tag, ".gasFees"));
        op.paymasterAndData = svm.createBytes(BYTES_LEN, string.concat(tag, ".paymasterAndData"));
        op.signature = svm.createBytes(BYTES_LEN, string.concat(tag, ".signature"));
    }

    function _assumeNoEip7702InitCode(PackedUserOperation memory op) internal pure {
        // Avoid hitting Eip7702Support._getEip7702Delegate which reads extcode of `sender`.
        // The 7702 path is exercised by integration tests; this Halmos check focuses on the
        // pure-hash structural properties, so we exclude the 7702 marker prefix.
        // Marker is bytes2(0x7702) at start of initCode (cast to bytes20 with zero padding).
        if (op.initCode.length >= 2) {
            bytes2 prefix;
            bytes memory ic = op.initCode;
            assembly {
                prefix := mload(add(ic, 0x20))
            }
            vm.assume(prefix != bytes2(0x7702));
        }
    }

    // ---------- check 1: determinism ----------

    function checkDeterministic() external {
        PackedUserOperation memory op = _symOp("op");
        _assumeNoEip7702InitCode(op);

        bytes32 h1 = wrapper.hashOf(ep, op);
        bytes32 h2 = wrapper.hashOf(ep, op);
        assertEq(h1, h2, "same input must hash the same");
    }

    // ---------- check 2: chain-id independence ----------

    function checkChainIdIndependent() external {
        PackedUserOperation memory op = _symOp("op");
        _assumeNoEip7702InitCode(op);

        uint64 chainA = uint64(svm.createUint(64, "chainA"));
        uint64 chainB = uint64(svm.createUint(64, "chainB"));
        vm.assume(chainA != 0 && chainB != 0);
        vm.assume(chainA != chainB);

        vm.chainId(chainA);
        bytes32 hA = wrapper.hashOf(ep, op);
        vm.chainId(chainB);
        bytes32 hB = wrapper.hashOf(ep, op);

        assertEq(hA, hB, "chainAgnostic hash must not depend on block.chainid");
    }

    // ---------- check 3a: sender-sensitive ----------

    function checkSensitiveToSender() external {
        PackedUserOperation memory op1 = _symOp("op");
        _assumeNoEip7702InitCode(op1);

        PackedUserOperation memory op2 = _cloneOp(op1);
        address altSender = svm.createAddress("altSender");
        vm.assume(altSender != op1.sender);
        op2.sender = altSender;

        bytes32 h1 = wrapper.hashOf(ep, op1);
        bytes32 h2 = wrapper.hashOf(ep, op2);
        assertNotEq(h1, h2, "flipping sender must change hash");
    }

    // ---------- check 3b: nonce-sensitive ----------

    function checkSensitiveToNonce() external {
        PackedUserOperation memory op1 = _symOp("op");
        _assumeNoEip7702InitCode(op1);

        PackedUserOperation memory op2 = _cloneOp(op1);
        uint256 altNonce = svm.createUint256("altNonce");
        vm.assume(altNonce != op1.nonce);
        op2.nonce = altNonce;

        bytes32 h1 = wrapper.hashOf(ep, op1);
        bytes32 h2 = wrapper.hashOf(ep, op2);
        assertNotEq(h1, h2, "flipping nonce must change hash");
    }

    // ---------- check 3c: callData-sensitive ----------

    function checkSensitiveToCallData() external {
        PackedUserOperation memory op1 = _symOp("op");
        _assumeNoEip7702InitCode(op1);

        PackedUserOperation memory op2 = _cloneOp(op1);
        bytes memory altCallData = svm.createBytes(BYTES_LEN, "altCallData");
        vm.assume(keccak256(altCallData) != keccak256(op1.callData));
        op2.callData = altCallData;

        bytes32 h1 = wrapper.hashOf(ep, op1);
        bytes32 h2 = wrapper.hashOf(ep, op2);
        assertNotEq(h1, h2, "flipping callData must change hash");
    }

    // ---------- check 3d: accountGasLimits-sensitive ----------

    function checkSensitiveToAccountGasLimits() external {
        PackedUserOperation memory op1 = _symOp("op");
        _assumeNoEip7702InitCode(op1);

        PackedUserOperation memory op2 = _cloneOp(op1);
        bytes32 altGasLimits = svm.createBytes32("altGasLimits");
        vm.assume(altGasLimits != op1.accountGasLimits);
        op2.accountGasLimits = altGasLimits;

        bytes32 h1 = wrapper.hashOf(ep, op1);
        bytes32 h2 = wrapper.hashOf(ep, op2);
        assertNotEq(h1, h2, "flipping accountGasLimits must change hash");
    }

    // ---------- internal: shallow clone (bytes fields are not copied; we reuse refs since
    // we only mutate the field under test in the calling check) ----------

    function _cloneOp(PackedUserOperation memory src) internal pure returns (PackedUserOperation memory dst) {
        dst.sender = src.sender;
        dst.nonce = src.nonce;
        dst.initCode = src.initCode;
        dst.callData = src.callData;
        dst.accountGasLimits = src.accountGasLimits;
        dst.preVerificationGas = src.preVerificationGas;
        dst.gasFees = src.gasFees;
        dst.paymasterAndData = src.paymasterAndData;
        dst.signature = src.signature;
    }
}
