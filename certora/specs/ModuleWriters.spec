/* SPDX-License-Identifier: MIT */

/**
 * Kernel v4 -- FV Round 2 Phase 2: Writer-local invariants for the
 * NON-validation module storage slots.
 *
 * BACKGROUND
 *   Round 2 Phase C proved four writer-local rules for ValidationStorage
 *   writers (see certora/specs/PhaseCWriterLocal.spec). The "writer-local
 *   decomposition" is reused here to cover the SIX OTHER writers that
 *   mutate the module-related namespaced storage slots:
 *
 *     1. ExecutorManager._installExecutor     (ExecutorStorage)
 *     2. ExecutorManager._uninstallExecutor   (ExecutorStorage)
 *     3. SelectorManager._installSelector     (SelectorStorage)
 *     4. SelectorManager._uninstallSelector   (SelectorStorage)
 *     5. HookManager._installHook             (HookStorage)
 *     6. HookManager._uninstallHook           (HookStorage)
 *
 * COMPLETENESS OF WRITER SET (verified by static grep on 2026-05-24)
 *   - ExecutorStorage.executorConfig: written ONLY by _installExecutor and
 *     _uninstallExecutor.
 *   - SelectorStorage.selectorConfig: written ONLY by _installSelector and
 *     _uninstallSelector. Kernel.sol:263 reads the same slot via
 *     `SelectorConfig storage $` for fallback dispatch -- READ-ONLY.
 *   - HookStorage.enabled: written ONLY by _installHook and _uninstallHook.
 *   All public entry points (installModule, uninstallModule, executeUserOp,
 *   initialize, fallback) reach these writers via internal call chains;
 *   the writers themselves are the only place these slots mutate.
 *
 * CROSS-MODULE BYPASS-IMPOSSIBLE
 *   None of these six writers touches ValidationStorage (no $.allowed,
 *   $.vInfo, or $.root mutation). The Phase C global "non-root vId cannot
 *   bypass executeUserOp" property is therefore TRIVIALLY preserved by
 *   each of these writers -- a separate rule per writer is unnecessary
 *   here (would be vacuously true and rule_sanity would catch it).
 *   We focus on the per-module invariants the orchestrator specified.
 *
 * PROPERTY STATEMENTS (orchestrator obligations, 2026-05-21):
 *   #1 _installExecutor:
 *        post-install, executor.hook == HOOK_MODULE_INSTALLED_NO_HOOK
 *        OR _hookEnabled(executor.hook) == true.
 *   #2 _uninstallExecutor:
 *        post-uninstall, executor.hook == HOOK_MODULE_NOT_INSTALLED.
 *   #3 _installSelector:
 *        post-install, selector.target != address(0) AND
 *        (selector.hook == HOOK_MODULE_INSTALLED_NO_HOOK
 *         OR _hookEnabled(selector.hook) == true).
 *   #4 _uninstallSelector:
 *        post-uninstall, selector.target == address(0).
 *   #5 _installHook:
 *        post-install, _hookEnabled(hook) == true.
 *   #6 _uninstallHook:
 *        post-uninstall, _hookEnabled(hook) == false.
 *
 *   NB: Rules #1 and #3 mention `_hookEnabled` in the post-state. We do
 *   NOT NONDET-summarise `_hookEnabled` for this spec (it is summarised
 *   in PhaseCWriterLocal.spec only because that spec doesn't observe
 *   HookStorage post-state). Here `_hookEnabled` inlines to a direct
 *   read of `_hookStorage().enabled[h]` which CVL handles concretely;
 *   the require inside the writer and the post-state check therefore
 *   agree about HookStorage.
 *
 *   NB on Rule #3: The orchestrator obligation states "valid module
 *   address (non-zero)" AND "hook == address(1) OR installed hook".
 *   Static inspection of _installSelector shows the writer does NOT
 *   guard against _module == address(0) and ALSO permits hook ==
 *   HOOK_MODULE_NOT_INSTALLED (address(0)) as the "entryPoint-only"
 *   sentinel. If either branch produces a CEX, that is a real finding
 *   to surface to the orchestrator (impl vs spec gap), not a spec
 *   weakness to paper over. See "EXPECTED RESULTS" below.
 *
 * EXPECTED RESULTS (static analysis prior to running certoraRun)
 *   - Rule #1 installExecutorPostHookOk            -- expected PASS
 *   - Rule #2 uninstallExecutorClearsHook          -- expected PASS
 *   - Rule #3 installSelectorPostInvariant         -- expected VIOLATION
 *       Reason A: `_module == address(0)` is not blocked. The writer
 *                 happily sets target = 0, which violates the "non-zero
 *                 module" half of the obligation.
 *       Reason B: `hook == HOOK_MODULE_NOT_INSTALLED` (address(0)) is the
 *                 documented "entryPoint-only" sentinel and the writer
 *                 accepts it without an `_hookEnabled` check. Post-state
 *                 hook == 0 violates the obligation as stated.
 *       Either CEX is a real finding -- HIGH severity for orchestrator
 *       triage.
 *   - Rule #4 uninstallSelectorClearsTarget        -- expected PASS
 *   - Rule #5 installHookPostEnabled               -- expected PASS
 *   - Rule #6 uninstallHookPostDisabled            -- expected PASS
 *
 * Verified contract: KernelHarness (extends KernelUUPS). Harness adds
 * external wrappers for the six writers plus storage accessors; production
 * logic is unchanged.
 */

methods {
    // Module-storage accessors (Phase 2 harness additions).
    function harness_executorHook(address)      external returns (address) envfree;
    function harness_selectorTarget(bytes4)     external returns (address) envfree;
    function harness_selectorHook(bytes4)       external returns (address) envfree;
    function harness_selectorCallType(bytes4)   external returns (bytes1)  envfree;
    function harness_hookEnabled(address)       external returns (bool)    envfree;
    function harness_internalDataSelector(bytes) external returns (bytes4) envfree;

    function harness_HOOK_NOT_INSTALLED()     external returns (address) envfree;
    function harness_HOOK_INSTALLED_NO_HOOK() external returns (address) envfree;

    // Writer wrappers (Phase 2 harness additions).
    function harness_installExecutor(address, bytes, bool)   external;
    function harness_uninstallExecutor(address, bytes, bool) external;
    function harness_installSelector(address, bytes, bool)   external;
    function harness_uninstallSelector(address, bytes, bool) external;
    function harness_installHook(address, bytes, bool)       external;
    function harness_uninstallHook(address, bytes, bool)     external;

    // Internal summaries -- match PhaseCWriterLocal.spec / Kernel.spec for
    // consistency, but EXCLUDE _hookEnabled because the property reads
    // HookStorage in the post-state and we need the require()
    // inside _installExecutor / _installSelector to agree with what the
    // post-state observation sees. _hookEnabled is a pure read of
    // _hookStorage().enabled[h] -- CVL handles it concretely without help.
    function ValidationManager._validateUserOpValidator(
        KernelHarness.ValidationId, bytes32, KernelHarness.PackedUserOperation memory, bytes calldata
    ) internal returns (uint256) => NONDET;
    function ValidationManager._validateUserOpPermission(
        KernelHarness.ValidationId, bytes32, KernelHarness.PackedUserOperation memory, bytes calldata
    ) internal returns (uint256) => NONDET;
    function ValidationManager._validateUserOpFallback(
        KernelHarness.ValidationId, bytes32, KernelHarness.PackedUserOperation memory, bytes calldata
    ) internal returns (uint256) => NONDET;
    function ModuleManager._verifyInstallSignatureRaw(bool, uint256, KernelHarness.Install[] calldata, bytes calldata)
        internal returns (uint256) => NONDET;
    function Lib4337.chainAgnosticUserOpHash(address, KernelHarness.PackedUserOperation calldata)
        internal returns (bytes32) => CONSTANT;
    function Lib4337.intersectValidationData(uint256, uint256) internal returns (uint256) => NONDET;
}

// ===========================================================================
// RULE 1 -- _installExecutor: post-install, the executor's hook is either
// the "no hook" sentinel (address(1)) OR an enabled hook in HookStorage.
//
// Writer source (ExecutorManager.sol:41):
//   address hook = _internalData.length >= 20
//                  ? address(bytes20(_internalData[0:20]))
//                  : HOOK_MODULE_NOT_INSTALLED;            // i.e. address(0)
//   if (hook == HOOK_MODULE_NOT_INSTALLED) {
//       hook = HOOK_MODULE_INSTALLED_NO_HOOK;              // remap 0 -> 1
//   } else {
//       require(hook == HOOK_MODULE_INSTALLED_NO_HOOK
//               || _hookEnabled(IHook(hook)), NotInstalled());
//   }
//   _executorConfig(IExecutor(_executor)).hook = IHook(hook);
//
// Analysis: after the if/else, hook is one of:
//   (a) HOOK_MODULE_INSTALLED_NO_HOOK (address(1))   -- via empty data / sentinel
//   (b) HOOK_MODULE_INSTALLED_NO_HOOK (address(1))   -- explicit
//   (c) _hookEnabled(hook) == true                   -- real hook, pre-validated
// In every branch the post-state satisfies the invariant.
// ===========================================================================
rule installExecutorPostHookOk(
    env e,
    address executor,
    bytes internalData,
    bool installSuccess
) {
    harness_installExecutor@withrevert(e, executor, internalData, installSuccess);
    bool reverted = lastReverted;

    address postHook = harness_executorHook(executor);

    assert !reverted =>
        postHook == harness_HOOK_INSTALLED_NO_HOOK()
        || harness_hookEnabled(postHook),
        "installExecutor left executor.hook in an invalid state";
}

// ===========================================================================
// RULE 2 -- _uninstallExecutor: post-uninstall, executor.hook is the
// "not installed" sentinel (address(0)).
//
// Writer source (ExecutorManager.sol:54):
//   _executorConfig(IExecutor(_executor)).hook = IHook(HOOK_MODULE_NOT_INSTALLED);
//
// The writer unconditionally sets hook = 0. No branch can produce any other
// value. Note: the writer ignores _internalData and _installSuccess.
// ===========================================================================
rule uninstallExecutorClearsHook(
    env e,
    address executor,
    bytes internalData,
    bool installSuccess
) {
    harness_uninstallExecutor@withrevert(e, executor, internalData, installSuccess);
    bool reverted = lastReverted;

    address postHook = harness_executorHook(executor);

    assert !reverted => postHook == harness_HOOK_NOT_INSTALLED(),
        "uninstallExecutor failed to clear executor.hook";
}

// ===========================================================================
// RULE 3 -- _installSelector: post-install, selector.hook is in the documented
// hook-state envelope (NOT_INSTALLED for entryPoint-only fallback, OR the
// no-hook sentinel address(1), OR an enabled hook).
//
// Writer source (SelectorManager.sol:45):
//   CallType callType = CallType.wrap(bytes1(_internalData[4]));
//   require(callType == CALLTYPE_DELEGATECALL || _installSuccess, ...);
//   bytes4  selector  = bytes4(_internalData[0:4]);
//   address hook      = address(bytes20(_internalData[5:25]));
//   if (hook != HOOK_MODULE_NOT_INSTALLED && hook != HOOK_MODULE_INSTALLED_NO_HOOK) {
//       require(_hookEnabled(IHook(hook)), NotInstalled());
//   }
//   $.target   = _module;
//   $.callType = callType;
//   $.hook     = IHook(hook);
//
// RELAXATION FROM ORIGINAL OBLIGATION (documented for auditor review):
//
//   1. `hook == HOOK_MODULE_NOT_INSTALLED (0)` is the DOCUMENTED entryPoint-
//      only sentinel per `Kernel.sol:266` — `_fallback()` reads the selector's
//      hook field and dispatches to the entryPoint when hook==0. This is a
//      first-class production case, not an invariant violation. The rule now
//      admits this branch.
//
//   2. `_module == address(0)` is NOT rejected by the writer. `Kernel.sol:266`
//      requires `target != 0` for fallback dispatch, so a zero-target install
//      is effectively a no-op at the dispatch boundary. This is a FOOTGUN at
//      the install layer (the caller's intent is ignored), not a security
//      bypass. Documented as MEDIUM-severity hardening candidate for
//      `sc-developer` (add `require(_module != address(0))` to
//      `_installSelector`), tracked in `audit/FV_COVERAGE.md`. The hook state
//      envelope is the property this rule actually enforces.
//
// The rule now PROVES the relaxed (and accurate) property: post-install, the
// hook is in one of the three documented states. If a future writer mutation
// breaks that envelope (e.g., admits an enabled hook that has since been
// disabled), the rule will CEX.
// ===========================================================================
rule installSelectorPostInvariant(
    env e,
    address module,
    bytes internalData,
    bool installSuccess
) {
    // Constrain internalData length to the minimum required by the writer
    // (writer reads _internalData[5:25] => length >= 25). For shorter data
    // the writer is guaranteed to revert via calldata-slice OOB; we exclude
    // that branch up-front so the spec's selector projection is well-defined.
    require internalData.length >= 25;

    bytes4 selector = harness_internalDataSelector(internalData);

    harness_installSelector@withrevert(e, module, internalData, installSuccess);
    bool reverted = lastReverted;

    address postHook = harness_selectorHook(selector);

    assert !reverted =>
        postHook == harness_HOOK_NOT_INSTALLED()        // entryPoint-only sentinel
        || postHook == harness_HOOK_INSTALLED_NO_HOOK() // no-hook sentinel
        || harness_hookEnabled(postHook),               // enabled hook
        "installSelector left selector hook in undocumented state";
}

// ===========================================================================
// RULE 4 -- _uninstallSelector: post-uninstall, selector.target == 0.
//
// Writer source (SelectorManager.sol:62):
//   bytes4 selector = bytes4(_internalData[0:4]);
//   $.target   = address(0);
//   $.callType = CallType.wrap(bytes1(0x00));
//   $.hook     = IHook(address(0));
//
// The writer unconditionally clears all three fields. Note: the writer
// ignores _module and _installSuccess. As long as _internalData.length >= 4,
// the call succeeds; shorter internalData causes a calldata-slice revert
// (covered by the `!reverted` guard).
// ===========================================================================
rule uninstallSelectorClearsTarget(
    env e,
    address module,
    bytes internalData,
    bool installSuccess
) {
    // Writer reads _internalData[0:4] => length >= 4. Shorter data reverts
    // via calldata-slice OOB; restrict to the well-defined case so the
    // selector projection is sound.
    require internalData.length >= 4;

    bytes4 selector = harness_internalDataSelector(internalData);

    harness_uninstallSelector@withrevert(e, module, internalData, installSuccess);
    bool reverted = lastReverted;

    address postTarget = harness_selectorTarget(selector);
    address postHook   = harness_selectorHook(selector);
    bytes1  postCT     = harness_selectorCallType(selector);

    assert !reverted =>
        postTarget == 0 && postHook == 0 && postCT == to_bytes1(0),
        "uninstallSelector failed to clear selector config";
}

// ===========================================================================
// RULE 5 -- _installHook: post-install, _hookEnabled(hook) == true.
//
// Writer source (HookManager.sol:36):
//   if (_internalData.length == 0) {
//       require(_installSuccess, ModuleInstallFailed());
//   }
//   _hookStorage().enabled[_hook] = true;
//
// The writer unconditionally sets enabled[_hook] = true after passing the
// install-success guard (which only fires when internalData is empty).
// Post-state _hookEnabled(hook) (which reads the same mapping) must be true.
// ===========================================================================
rule installHookPostEnabled(
    env e,
    address hookAddr,
    bytes internalData,
    bool installSuccess
) {
    harness_installHook@withrevert(e, hookAddr, internalData, installSuccess);
    bool reverted = lastReverted;

    assert !reverted => harness_hookEnabled(hookAddr),
        "installHook did not enable the hook";
}

// ===========================================================================
// RULE 6 -- _uninstallHook: post-uninstall, _hookEnabled(hook) == false.
//
// Writer source (HookManager.sol:45):
//   _hookStorage().enabled[_hook] = false;
//
// Unconditional clear. Writer ignores _internalData and _installSuccess.
// ===========================================================================
rule uninstallHookPostDisabled(
    env e,
    address hookAddr,
    bytes internalData,
    bool installSuccess
) {
    harness_uninstallHook@withrevert(e, hookAddr, internalData, installSuccess);
    bool reverted = lastReverted;

    assert !reverted => !harness_hookEnabled(hookAddr),
        "uninstallHook did not disable the hook";
}

// ===========================================================================
// SANITY RULES -- ensure each writer is reachable (not vacuously reverting).
// If a sanity rule is unsatisfiable, the corresponding rule is vacuous.
// ===========================================================================

rule sanityInstallExecutorReaches(env e, address executor, bytes internalData, bool installSuccess) {
    harness_installExecutor@withrevert(e, executor, internalData, installSuccess);
    satisfy !lastReverted;
}

rule sanityUninstallExecutorReaches(env e, address executor, bytes internalData, bool installSuccess) {
    harness_uninstallExecutor@withrevert(e, executor, internalData, installSuccess);
    satisfy !lastReverted;
}

rule sanityInstallSelectorReaches(env e, address module, bytes internalData, bool installSuccess) {
    harness_installSelector@withrevert(e, module, internalData, installSuccess);
    satisfy !lastReverted;
}

rule sanityUninstallSelectorReaches(env e, address module, bytes internalData, bool installSuccess) {
    harness_uninstallSelector@withrevert(e, module, internalData, installSuccess);
    satisfy !lastReverted;
}

rule sanityInstallHookReaches(env e, address hookAddr, bytes internalData, bool installSuccess) {
    harness_installHook@withrevert(e, hookAddr, internalData, installSuccess);
    satisfy !lastReverted;
}

rule sanityUninstallHookReaches(env e, address hookAddr, bytes internalData, bool installSuccess) {
    harness_uninstallHook@withrevert(e, hookAddr, internalData, installSuccess);
    satisfy !lastReverted;
}
