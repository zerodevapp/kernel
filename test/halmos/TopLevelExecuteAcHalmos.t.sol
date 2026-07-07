pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {KernelUUPS} from "src/KernelUUPS.sol";
import {IERC7579Account} from "src/interfaces/IERC7579Account.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

/// @notice Symbolic verification of the top-level access control on
/// `Kernel.execute` and `Kernel.executeFromExecutor`.
///
/// Properties under test:
///   1. `execute(bytes32, bytes)` is gated by `_onlyEntryPointOrSelf` — it MUST
///      revert for every caller that is not `ENTRYPOINT` and not `address(this)`.
///   2. `executeFromExecutor(bytes32, bytes)` is gated by the `executorHook`
///      modifier, which loads `_executorConfig(IExecutor(msg.sender)).hook` and
///      requires it to be non-zero. So the function MUST revert for every caller
///      whose executor config slot is still zero (i.e. anyone except an installed
///      executor module).
///
/// We deploy `KernelUUPS` directly (no ERC1967 proxy) — neither `execute` nor
/// `executeFromExecutor` carries Solady's `onlyProxy` modifier, so the
/// implementation address is itself a valid call surface and `address(this)`
/// resolves to the implementation. This mirrors `KernelExecutorHalmos`, which
/// already proves the executor success-path against the same direct deployment.
contract TopLevelExecuteAcHalmos is SymTest, Test {
    KernelUUPS kernel;
    address entryPoint;
    address installedExecutor;

    function setUp() external {
        entryPoint = makeAddr("EntryPoint");
        kernel = new KernelUUPS(IEntryPoint(entryPoint));
        installedExecutor = address(0xdeadbeef);
        // Install one executor module so the success-path test for
        // `executeFromExecutor` has a caller whose config hook is non-zero.
        // `_installExecutor` defaults the hook to `address(1)` when no hook is
        // supplied in `internalData`.
        vm.startPrank(entryPoint);
        kernel.installModule(2, installedExecutor, abi.encode(hex"", ""));
        vm.stopPrank();
    }

    // --- execute(bytes32, bytes) ------------------------------------------------

    /// @notice Any caller other than the EntryPoint or the kernel itself must be
    /// rejected by `Kernel.execute`'s `_onlyEntryPointOrSelf` gate.
    function checkExecuteRevertsForArbitraryCaller() external {
        address caller = svm.createAddress("caller");
        vm.assume(caller != entryPoint);
        vm.assume(caller != address(kernel));

        bytes memory executionData = _validExecutionData();
        bytes32 mode = bytes32(0); // CALLTYPE_SINGLE | EXECTYPE_DEFAULT

        vm.prank(caller);
        (bool ok,) = address(kernel).call(abi.encodeWithSelector(IERC7579Account.execute.selector, mode, executionData));
        assertFalse(ok, "arbitrary caller must not be allowed to execute");
    }

    /// @notice The EntryPoint must clear the access gate on `Kernel.execute`.
    function checkExecuteSucceedsForEntryPoint() external {
        bytes memory executionData = _validExecutionData();
        bytes32 mode = bytes32(0);

        vm.prank(entryPoint);
        (bool ok,) = address(kernel).call(abi.encodeWithSelector(IERC7579Account.execute.selector, mode, executionData));
        assertTrue(ok, "EntryPoint must be allowed to execute");
    }

    /// @notice A self-call (kernel calling itself) must clear the access gate.
    function checkExecuteSucceedsForSelf() external {
        bytes memory executionData = _validExecutionData();
        bytes32 mode = bytes32(0);

        vm.prank(address(kernel));
        (bool ok,) = address(kernel).call(abi.encodeWithSelector(IERC7579Account.execute.selector, mode, executionData));
        assertTrue(ok, "self-call must be allowed to execute");
    }

    // --- executeFromExecutor(bytes32, bytes) -----------------------------------

    /// @notice Any caller whose executor config still holds the zero hook (i.e.
    /// not installed as an executor module) must be rejected by the
    /// `executorHook` modifier on `executeFromExecutor`.
    function checkExecuteFromExecutorRevertsForUninstalledExecutor() external {
        address caller = svm.createAddress("caller");
        // The only installed executor is `installedExecutor`. Every other address
        // has `_executorConfig(...).hook == address(0)`, so it must be rejected.
        vm.assume(caller != installedExecutor);

        bytes memory executionData = _validExecutionData();
        bytes32 mode = bytes32(0);

        vm.prank(caller);
        (bool ok,) = address(kernel)
            .call(abi.encodeWithSelector(IERC7579Account.executeFromExecutor.selector, mode, executionData));
        assertFalse(ok, "uninstalled executor must not be allowed to executeFromExecutor");
    }

    /// @notice An installed executor module must clear the `executorHook` gate
    /// on `executeFromExecutor`.
    function checkExecuteFromExecutorSucceedsForInstalledExecutor() external {
        bytes memory executionData = _validExecutionData();
        bytes32 mode = bytes32(0);

        vm.prank(installedExecutor);
        (bool ok,) = address(kernel)
            .call(abi.encodeWithSelector(IERC7579Account.executeFromExecutor.selector, mode, executionData));
        assertTrue(ok, "installed executor must be allowed to executeFromExecutor");
    }

    // --- helpers ----------------------------------------------------------------

    /// @dev Builds a well-formed single-call execution payload that targets an
    /// EOA-like address with empty data. `LibERC7579.decodeSingle` requires the
    /// payload length to exceed 0x33 (52 bytes), so we include a 1-byte tail.
    /// `_call` against a code-less address returns `success = true`, so the
    /// success-path checks do not revert inside `_execute`.
    function _validExecutionData() internal pure returns (bytes memory) {
        address target = address(0xCAFE);
        uint256 value = 0;
        bytes1 pad = 0x00;
        return abi.encodePacked(target, value, pad);
    }
}
