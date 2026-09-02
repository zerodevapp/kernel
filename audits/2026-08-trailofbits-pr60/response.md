# Response — Trail of Bits, Kernel v4 PR #60 (Summary Report, 2026-08-28)

Assessed revision: `62db9981ab921129be67637df9a5f3095dda2749`
Response branch: `feat/permission-hook-module-type`

| ID | Finding | Severity | Disposition |
|----|---------|----------|-------------|
| TOB-KERNEL-1 | Raw ERC-1271 validator replay | Medium | **Fixed** — `b8861c6` |
| TOB-KERNEL-2 | Modules active during uninstall callbacks | Medium | **Fixed** — `ded1250`, `dc7a748` |
| TOB-KERNEL-3 | Bundle-level revocation finality | Undetermined | **Acknowledged** |
| TOB-KERNEL-4 | Signed-install front-running | Medium | **Acknowledged** |
| TOB-KERNEL-5 | Raw validation aborts ERC-7739 | Informational | **Fixed (raw path)** — `b8861c6`; residual acknowledged |
| TOB-KERNEL-6 | Replayable mode violates ERC-7562 | Informational | **Acknowledged** |
| TOB-KERNEL-7 | Root permission policy removal | Medium | **Fixed** — `498a61e` |
| TOB-KERNEL-8 | Shared scoped-hook deinitialization | Low | **Acknowledged** |
| TOB-KERNEL-9 | In-flight scoped-hook removal | Medium | **Fixed** — `73e64bb` |
| TOB-KERNEL-10 | Unchecked initData decoding | Medium | **Fixed** — `d92c9a2` |
| TOB-KERNEL-11 | Ignored executor callback failures | Medium | **Acknowledged** (documented in code) |
| TOB-KERNEL-12 | Missing executor installation check | Medium | **Fixed** — `bac0d4b` |
| TOB-KERNEL-13 | Unbound userOpHash in executeUserOp | Low | **Fixed** — `6fabfea` |

Every fix ships with a regression test named for its window (`test/unit/`): `Erc1271AccountBinding`,
`ExecutorRevocation`, `PolicyRootUninstall`, `WrongTypeUninstall`, `SetRootTeardownOrder`,
`HookFrameGuard`, `InstallDataBounds`, `ExecuteUserOpBinding`.

## Fix notes

- **TOB-1** — raw ERC-1271 now resolves only against the fallback signer
  (`ModuleManager._erc1271Raw`), whose key *is* the account address. Type-prefixed signatures always
  take the nested EIP-712 path; the prefixed-raw convention (`0x00 ‖ sig`) was deliberately dropped
  and its test flipped to assert rejection.
- **TOB-2** — `_uninstall` revokes state before the callback; `setRoot(removeCurrent)` teardown is
  fully two-phase (all state — hook pointer, policies, signer, installed — cleared before any
  `onUninstall` fires). Callback failures never block removal.
- **TOB-7** — `_uninstallPolicy` now enforces `CannotUninstallRoot`, matching validators and
  signers. Root policy changes require an explicit root rotation.
- **TOB-9** — a transient `hookFrameDepth` counter brackets every hook-protected frame
  (`executeUserOp`, `executeFromExecutor`, fallback); scoped-hook removal reverts with
  `ScopedExecutionHookFrameActive` while nonzero.
- **TOB-10** — `installModule`/`uninstallModule` route through `_decodeModuleData`, which requires
  both dynamic fields of `InstallModuleDataFormat` to lie entirely within the declared `initData`.
- **TOB-12** — `_uninstallExecutor` requires `installed`; same-class checks added to
  `_uninstallValidator` (installed) and `_uninstallSelector` (module must match the selector's
  target). New error: `ModuleNotInstalled`.
- **TOB-13** — `executeUserOp` is EntryPoint-only, and `_processUserOp` rejects
  `executeUserOp`-wrapping-`executeUserOp` (the delegatecall-nested variant keeps
  `msg.sender == ENTRYPOINT`, so the auth change alone would not have closed it).

## Acknowledgment rationale

- **TOB-3 (bundle-level revocation)** — the described bundle attack is strictly dominated by plain
  front-running: an attacker who can observe the revocation operation can equally submit their own
  transaction with the still-valid authority ahead of it, which no ERC-4337 account can prevent.
  Revocation finality is therefore bounded by transaction ordering, not by the bundle mechanics.
  The proposed per-`userOpHash` authorization epoch would add a storage write to every operation
  without changing that bound. Won't fix. Documented per reviewer request (README "Known
  limitations" and the `validateUserOp` NatSpec): a validator uninstall or root replacement that
  executes earlier in a `handleOps` bundle does not invalidate a later operation in that same
  bundle, which was already validated against the now-revoked authority.
- **TOB-4 (signed-install front-running)** — the attacker gains no authority: replaying the signed
  install through the standalone route installs exactly the modules the owner signed; the impact is
  griefing (the victim's pending enable-mode operation fails and the bundle may revert). We accept
  this rather than domain-separating the two routes, which would break signature compatibility for
  integrators. Wallets can avoid the race by preferring the standalone route or fresh nonce keys.
- **TOB-5 (residual)** — the raw-path abort is fixed (`b8861c6`); what remains is that a validator
  that *reverts* instead of returning a failure value inside one nested branch aborts the sibling
  branch. Module quality requirement: validators must return `0xffffffff`-style failures rather
  than reverting on malformed input, which the module guidelines document.
- **TOB-6 (ERC-7562)** — acknowledged as a deployment constraint, not fixed: replayable-mode
  UserOperations call `eip712Domain()` on the EntryPoint during validation and are rejected by
  conformant public bundlers. Replayable mode remains supported for self-bundled flows and direct
  `handleOps` submission, which is how it is used today. Revisit (precompute the sans-chain-id
  domain separator at construction) if public-mempool support becomes a requirement.
- **TOB-8 (shared scoped hooks)** — hooks receive a per-attachment `id` in `preCheck`/`postCheck`
  and are expected to key their state by `(account, id)`; a hook written to that contract is
  unaffected by an account-wide `onUninstall` for a sibling attachment. We document the reuse
  contract instead of adding per-hook attachment refcounting. Note that TOB-9's frame guard already
  prevents the in-flight variant of this issue.
- **TOB-11 (executor install ignores onInstall)** — intentional, now documented at the site
  (`ExecutorManager._installExecutor`): executors may be EOAs or contracts that do not implement
  `IModule`, so lifecycle callbacks are best-effort for this module type. The exploitable half of
  the reported chain is closed by `ded1250` (revocation is unconditional); the remaining
  trade-off — reinstalling a stateful executor whose `onInstall` reverts re-activates its previous
  state — is accepted and placed on the installer.
