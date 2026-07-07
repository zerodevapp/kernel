pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {MockCallee} from "../mock/MockCallee.sol";
import {ExecutionManager} from "src/core/ExecutionManager.sol";

/// @notice Concrete harness exposing the internal `_executeCall` and
/// `_executeDelegateCall` functions of {ExecutionManager}, plus the
/// two `onRevert` function pointers, so symbolic execution can drive
/// them directly.
contract ExecutionManagerHarness is ExecutionManager {
    // ---- onRevert flag ----
    // We expose two entrypoints (Throw / Silent variants) rather than
    // passing a function pointer through external calldata (which Solidity
    // does not allow) — internally each entrypoint selects the matching
    // internal `function()` pointer.

    function callThrow(bytes calldata executionData) external returns (bytes[] memory) {
        return _executeCall(executionData, _onRevertThrow);
    }

    function callSilent(bytes calldata executionData) external returns (bytes[] memory) {
        return _executeCall(executionData, _onRevertSilent);
    }

    function delegateThrow(bytes calldata executionData) external returns (bytes[] memory) {
        return _executeDelegateCall(executionData, _onRevertThrow);
    }

    function delegateSilent(bytes calldata executionData) external returns (bytes[] memory) {
        return _executeDelegateCall(executionData, _onRevertSilent);
    }
}

/// @notice Halmos symbolic proofs over the single-call and single-delegatecall
/// execution paths in {ExecutionManager}.
///
/// Properties:
///   1. Return-data shape is preserved bit-for-bit when the underlying call
///      succeeds, for each documented size class.
///   2. Reverts propagate when `onRevert == _onRevertThrow`.
///   3. Reverts are swallowed when `onRevert == _onRevertSilent`.
///
/// The same three properties are proved for the delegatecall variant.
contract ExecuteCallHalmos is SymTest, Test {
    ExecutionManagerHarness harness;
    MockCallee callee;

    function setUp() external {
        harness = new ExecutionManagerHarness();
        callee = new MockCallee();
    }

    // -------------------------------------------------------------------
    // _executeCall — return-data shape preserved (bit-for-bit)
    // -------------------------------------------------------------------

    function checkExecuteCallReturn0() external {
        // `data.length == 0` still produces a 120-byte executionData
        // (20 addr + 32 value + 4 selector + 32 offset + 32 len + 0 data),
        // well above the 0x33 minimum required by `LibERC7579.decodeSingle`.
        _executeCallReturnShape(0);
    }

    function checkExecuteCallReturn32() external {
        _executeCallReturnShape(32);
    }

    function checkExecuteCallReturn64() external {
        _executeCallReturnShape(64);
    }

    function checkExecuteCallReturn256() external {
        _executeCallReturnShape(256);
    }

    // -------------------------------------------------------------------
    // _executeDelegateCall — return-data shape preserved (bit-for-bit)
    // -------------------------------------------------------------------

    function checkExecuteDelegateCallReturn0() external {
        // `data.length == 0` produces 20 + 4 + 32 + 32 + 0 = 88 bytes of
        // executionData for delegatecall — above the 0x13 minimum.
        _executeDelegateCallReturnShape(0);
    }

    function checkExecuteDelegateCallReturn32() external {
        _executeDelegateCallReturnShape(32);
    }

    function checkExecuteDelegateCallReturn64() external {
        _executeDelegateCallReturnShape(64);
    }

    function checkExecuteDelegateCallReturn256() external {
        _executeDelegateCallReturnShape(256);
    }

    // -------------------------------------------------------------------
    // Revert propagation
    // -------------------------------------------------------------------

    /// @notice With `onRevert == _onRevertThrow`, a reverting callee MUST
    /// cause `_executeCall` itself to revert.
    function checkExecuteCallRevertPropagation() external {
        bytes memory innerCall = abi.encodeWithSelector(MockCallee.forceRevert.selector);
        bytes memory executionData = abi.encodePacked(address(callee), uint256(0), innerCall);

        (bool success,) =
            address(harness).call(abi.encodeWithSelector(ExecutionManagerHarness.callThrow.selector, executionData));
        assertFalse(success, "Throw variant must propagate revert");
    }

    /// @notice With `onRevert == _onRevertSilent`, a reverting callee MUST
    /// NOT cause `_executeCall` to revert — the outer call returns normally
    /// and `results.length == 1`.
    function checkExecuteCallRevertSwallowed() external {
        bytes memory innerCall = abi.encodeWithSelector(MockCallee.forceRevert.selector);
        bytes memory executionData = abi.encodePacked(address(callee), uint256(0), innerCall);

        bytes[] memory results = harness.callSilent(executionData);
        assertEq(results.length, 1, "Silent variant must return single slot");
    }

    /// @notice Delegate variant: with `_onRevertThrow`, a reverting target
    /// MUST cause `_executeDelegateCall` to revert.
    function checkExecuteDelegateCallRevertPropagation() external {
        bytes memory innerCall = abi.encodeWithSelector(MockCallee.forceRevert.selector);
        bytes memory executionData = abi.encodePacked(address(callee), innerCall);

        (bool success,) =
            address(harness).call(abi.encodeWithSelector(ExecutionManagerHarness.delegateThrow.selector, executionData));
        assertFalse(success, "Throw variant (delegate) must propagate revert");
    }

    /// @notice Delegate variant: with `_onRevertSilent`, a reverting target
    /// MUST NOT cause `_executeDelegateCall` to revert.
    function checkExecuteDelegateCallRevertSwallowed() external {
        bytes memory innerCall = abi.encodeWithSelector(MockCallee.forceRevert.selector);
        bytes memory executionData = abi.encodePacked(address(callee), innerCall);

        bytes[] memory results = harness.delegateSilent(executionData);
        assertEq(results.length, 1, "Silent variant (delegate) must return single slot");
    }

    // -------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------

    /// @dev Drives `_executeCall` against `MockCallee.ret(bytes)` with a
    /// symbolic `bytes` payload of length `length` and asserts the returned
    /// data is the exact same byte-string (compared via keccak256).
    function _executeCallReturnShape(uint256 length) internal {
        bytes memory data = svm.createBytes(length, "data");
        bytes memory innerCall = abi.encodeWithSelector(MockCallee.ret.selector, data);
        bytes memory executionData = abi.encodePacked(address(callee), uint256(0), innerCall);

        // Both onRevert variants must produce identical return-data on success.
        bytes[] memory r1 = harness.callThrow(executionData);
        bytes[] memory r2 = harness.callSilent(executionData);

        assertEq(r1.length, 1, "callThrow results.length");
        assertEq(r2.length, 1, "callSilent results.length");

        // r[0] is the abi-encoded `bytes` returned by MockCallee.ret —
        // decoding it yields the original symbolic `data` bit-for-bit.
        bytes memory actualThrow = abi.decode(r1[0], (bytes));
        bytes memory actualSilent = abi.decode(r2[0], (bytes));
        assertEq(keccak256(actualThrow), keccak256(data), "throw: return shape");
        assertEq(keccak256(actualSilent), keccak256(data), "silent: return shape");
    }

    /// @dev Same as `_executeCallReturnShape` but for `_executeDelegateCall`.
    /// Note: delegatecall runs `MockCallee.ret` in the harness's context;
    /// since `ret` is `pure` it does not touch storage and the return
    /// shape is identical.
    function _executeDelegateCallReturnShape(uint256 length) internal {
        bytes memory data = svm.createBytes(length, "data");
        bytes memory innerCall = abi.encodeWithSelector(MockCallee.ret.selector, data);
        bytes memory executionData = abi.encodePacked(address(callee), innerCall);

        bytes[] memory r1 = harness.delegateThrow(executionData);
        bytes[] memory r2 = harness.delegateSilent(executionData);

        assertEq(r1.length, 1, "delegateThrow results.length");
        assertEq(r2.length, 1, "delegateSilent results.length");

        bytes memory actualThrow = abi.decode(r1[0], (bytes));
        bytes memory actualSilent = abi.decode(r2[0], (bytes));
        assertEq(keccak256(actualThrow), keccak256(data), "delegate throw: return shape");
        assertEq(keccak256(actualSilent), keccak256(data), "delegate silent: return shape");
    }
}
