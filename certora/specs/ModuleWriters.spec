/* SPDX-License-Identifier: MIT */

/**
 * Kernel v4 writer-local invariants for executor and fallback-selector storage.
 * Generic hooks were removed; executor installation is represented by a bool,
 * and selector configuration contains only target and callType.
 */

methods {
    function harness_executorInstalled(address) external returns (bool) envfree;
    function harness_selectorTarget(bytes4) external returns (address) envfree;
    function harness_internalDataSelector(bytes) external returns (bytes4) envfree;

    function harness_installExecutor(address, bytes, bool) external;
    function harness_uninstallExecutor(address, bytes, bool) external;
    function harness_installSelector(address, bytes, bool) external;
    function harness_uninstallSelector(address, bytes, bool) external;
}

rule installExecutorMarksInstalled(env e, address executor, bytes internalData, bool installSuccess) {
    harness_installExecutor@withrevert(e, executor, internalData, installSuccess);
    bool reverted = lastReverted;
    assert !reverted => harness_executorInstalled(executor),
        "successful executor installation must set installed";
}

rule uninstallExecutorClearsInstalled(env e, address executor, bytes internalData, bool installSuccess) {
    harness_uninstallExecutor@withrevert(e, executor, internalData, installSuccess);
    bool reverted = lastReverted;
    assert !reverted => !harness_executorInstalled(executor),
        "successful executor uninstall must clear installed";
}

rule installSelectorSetsTarget(env e, address module, bytes internalData, bool installSuccess) {
    bytes4 selector = harness_internalDataSelector(internalData);
    harness_installSelector@withrevert(e, module, internalData, installSuccess);
    bool reverted = lastReverted;
    assert !reverted => harness_selectorTarget(selector) == module,
        "successful selector installation must set target";
}

rule uninstallSelectorClearsTarget(env e, address module, bytes internalData, bool installSuccess) {
    bytes4 selector = harness_internalDataSelector(internalData);
    harness_uninstallSelector@withrevert(e, module, internalData, installSuccess);
    bool reverted = lastReverted;
    assert !reverted => harness_selectorTarget(selector) == 0,
        "successful selector uninstall must clear target";
}
