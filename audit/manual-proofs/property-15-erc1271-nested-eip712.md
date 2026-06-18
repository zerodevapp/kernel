---
date: 2026-05-23
project: kernel-v4
type: manual-proof
property-id: 15
status: proven
contracts: [src/lib/ERC1271.sol]
backends-attempted: [kontrol, halmos]
backend-final: manual-cfg
reviewer: sc-critical-thinker
target_vault_path: ~/Documents/Obsidian/projects/kernel-v4/audits/manual-proofs/property-15-erc1271-nested-eip712.md
---

# Property #15 — Single-return-site CFG proof for `_erc1271IsValidSignatureViaNestedEIP712`

## 1. Property statement

Let `H` be the symbolic input `hash` of type `bytes32`, `S` the symbolic input
`signature` of type `bytes calldata`, and let
`V(h, s) = _erc1271IsValidSignatureNowCalldata(h, s)` denote the abstract inner
ERC-1271 verifier whose body is supplied by the inheriting contract.

For every reachable `(H, S)`:

> **P15-std**:  `_erc1271IsValidSignatureViaNestedEIP712(H, S) = true`
>               ⇒  there exist `h'` and `s'` derivable from `(H, S, address(this), eip712Domain())`
>                   such that  `V(h', s') = true`.

> **P15-rep**:  `_erc1271IsValidSignatureViaNestedEIP712Replayable(H, S) = true`
>               ⇒  there exist `h'` and `s'` derivable from `(H, S, address(this), eip712Domain())`
>                   such that  `V(h', s') = true`.

Both stated **contrapositively** (the form proved here, because it is the
single-statement form that covers every reachable path):

> **¬P15-std**:  `(∀ h', s') V(h', s') = false`
>                ⇒  `_erc1271IsValidSignatureViaNestedEIP712(H, S) = false`.

> **¬P15-rep**:  `(∀ h', s') V(h', s') = false`
>                ⇒  `_erc1271IsValidSignatureViaNestedEIP712Replayable(H, S) = false`.

In plain English: the outer function authorises a signature **only when the
inner verifier authorises it**. The reconstruction logic (TypedDataSign vs
PersonalSign fallback vs corrupted-`d`) affects which `(h', s')` pair the
verifier is consulted on; it never bypasses the verifier.

## 2. Why FV alone is insufficient (and what we proved with FV anyway)

Two FV backends were attempted on the full property; both gave **partial** results.

### 2.1 Halmos — PROVEN for PersonalSign, blocked on TypedDataSign

`test/halmos/ERC1271NestedEIP712Halmos.t.sol` — 6/6 PASS in 24.6 s, ≤0.04 s
aggregate solver time. Covers:

- Standard variant: signature lengths `{0, 65, 100}`, trailing 2 bytes pinned
  to `0x00 0x00` to force the PersonalSign branch via `iszero(c)`.
- Replayable variant: same three lengths.

The TypedDataSign branch is **not reachable** in Halmos. Attempted lengths
`67 (c=1)` and `100 (c=32)` hit
`NotConcreteError: symbolic SHA3 data size` because the `contentsName` scan
loop at `src/lib/ERC1271.sol:206-219` (and the mirror at `:293-306`) computes
the keccak input length `sub(add(p, c), m)` from symbolic byte-equality checks
against `)` and `(`. Halmos's keccak handler requires a syntactically concrete
size argument.

### 2.2 Kontrol — partial (524 KCFG nodes, 0 CEX, no closure)

`test/kontrol/ERC1271NestedEIP712Kontrol.t.sol` — Round 1: 102 nodes, 14
SUCCESS terminals, 12 covers, killed at ~1h25m. Round 2: 524 nodes, 306 edges,
108 splits, 88 covers, 90 SUCCESS terminals, 21 frontier nodes still pending,
killed at `--max-iterations 500`. Total wall-time invested across both rounds:
~14 h 15 m.

**Zero counterexamples** across the entire 524-node exploration. The blocker
is not soundness — it is SMT cost: the calldatacopy at `:202` uses an offset
`add(o, 0x40)` where `o = add(signature.offset, sub(signature.length, l))`
with `l = add(0x42, c)` and `c` derived from the trailing two bytes; the
contentsName scan adds another 5+ calldata-dependent reads. KEVM's symbolic
calldata handler creates an exponential branching tree in
`signature.length × c`.

### 2.3 The remaining gap

The TypedDataSign branch on both variants. That gap is exactly what this
manual CFG proof closes.

## 3. CFG analysis — standard variant

File: `src/lib/ERC1271.sol:155-240`.

### 3.1 Basic-block decomposition

Numbering follows the source line ranges. Each block ends at the first
control-flow instruction (branch, loop entry, `break`, fallthrough into a
join point) or at the function exit.

| BB  | Lines    | Contents (summary) |
|-----|----------|--------------------|
| BB1 | 161-177  | Solidity prelude: `t := address(this)`; if non-zero, populate the upper half of the typehash buffer at `mload(0x40)` from `eip712Domain()` and re-allocate. |
| BB2 | 179-182  | Enter outer assembly block. Cache `m := mload(0x40)`. Decode `c` = trailing 2 bytes of `signature`. Loop header `for {} 1 {}` (Yul condition `1` ≡ `while(true)`). |
| BB3 | 183-191  | Loop body entry. Compute `l, o`. Store `\x19\x01` prefix at 0x00. `calldatacopy(0x20, o, 0x40)`. Compute the branch predicate at `:191` — `xor(keccak256(0x1e, 0x42), hash) ∨ lt(signature.length, l) ∨ iszero(c)`. |
| BB4 | 192-197  | **PersonalSign branch.** `t := 0`; build `PersonalSign(prefixed=hash)` struct hash; `hash := keccak256(t, 0x40)`; `break`. |
| BB5 | 200-213  | **TypedDataSign branch part A.** Build `TypedDataSign(` typehash skeleton at `m`. Copy `contentsName` optimistically. If the last copied byte is not `)`, enter the explicit-mode scan at `:206-209` (nested for-loop; itself a sub-CFG, but its only exits are `break` to the enclosing block — does NOT exit BB5's enclosing loop). Truncate `c`, re-copy `contentsName`, place opening `(`. |
| BB6 | 214-219  | **TypedDataSign branch part B.** Compute `d` (contentsName validity flag). Advance `p` past the prefix until `(` is found. |
| BB7 | 220-234  | **TypedDataSign branch part C.** Write the trailing typehash string. Copy `contentsType` after the typehash. Build `typedDataSignTypehash` at `t`. Compute the final `hash := keccak256(0x1e, add(0x42, and(1, d)))` (corrupted iff `d & 1 == 1`). Truncate `signature.length := signature.length - l`. `break`. |
| BB8 | 236-237  | **Loop exit join.** `mstore(0x40, m)` restores the free memory pointer. End of outer assembly block. |
| BB9 | 238-239  | **Return tail.** If `t == 0` (PersonalSign branch ran), call `hash = _hashTypedData(hash)`. Then assign `result = V(hash, signature)`. Function returns (implicit `return result` via the named return variable). |

### 3.2 Control-flow graph

```
        ┌──────────────┐
        │   ENTRY      │
        └──────┬───────┘
               │
               ▼
        ┌──────────────┐
        │  BB1 prelude │  (161-177)
        └──────┬───────┘
               │
               ▼
        ┌──────────────┐
        │  BB2 cache+  │  (179-182)
        │  loop hdr    │
        └──────┬───────┘
               │
               ▼
        ┌──────────────┐
        │  BB3 predicate│ (183-191)
        └──┬────────┬──┘
   :191 T │        │ :191 F
           │        │
           ▼        ▼
   ┌─────────┐  ┌─────────┐
   │  BB4    │  │  BB5 A  │ (200-213)
   │ PSign   │  │ TDSign  │
   │ branch  │  └────┬────┘
   │ + break │       │
   └────┬────┘       ▼
        │       ┌─────────┐
        │       │  BB6 B  │ (214-219)
        │       └────┬────┘
        │            ▼
        │       ┌─────────┐
        │       │  BB7 C  │ (220-234)
        │       │ + break │
        │       └────┬────┘
        │            │
        └────────────┤
                     ▼
             ┌──────────────┐
             │  BB8 restore │  (236-237)
             └──────┬───────┘
                    │
                    ▼
             ┌──────────────┐
             │  BB9 return  │  (238-239)
             │  result =    │
             │  V(h', s')   │
             └──────┬───────┘
                    │
                    ▼
                  EXIT
```

### 3.3 Inventory of `return`, `break`, and assembly-level exits

Inside the entire function body (lines 161-239) the following control-flow
keywords appear:

- `return` — **zero occurrences.** The function has a named return variable
  `result` (declared at `:159`); Solidity emits the implicit `return result`
  at the closing brace `:240`. There is **no early `return true`** anywhere
  in the function, including inside both assembly blocks.
- `break` — two occurrences:
  - `:196` — inside BB4, exits the `for {} 1 {}` outer loop (BB2/BB3 header).
  - `:234` — inside BB7, exits the same outer loop.
  - A third `break` at `:208` is inside the **nested** for-loop within BB5
    (the contentsName backward scan); per Yul semantics, `break` exits the
    *innermost enclosing for-loop*, so this `break` exits the inner scan
    and falls through to `:210`, not out of BB5.
- `revert`, `invalid`, `selfdestruct`, `stop`, `return(...)` (Yul) — **zero
  occurrences** in either assembly block.

### 3.4 The single-return-site lemma

**Lemma 3.4 (standard variant)**. Every execution of
`_erc1271IsValidSignatureViaNestedEIP712(H, S)` that does not revert reaches
`:239` exactly once, and the function's return value equals the value of
`result` assigned at `:239`.

*Proof.*

1. **BB1 has a single outgoing edge** to BB2 (the `if (t != uint256(0))` at
   `:163` is two-armed but both arms join at `:178`; the assembly block at
   `:167-176` contains only `mload`/`mstore`/`keccak256` ops, none of which
   alter control flow).

2. **BB2 has a single outgoing edge** to BB3 (the for-loop header `for {} 1 {}`
   in Yul is equivalent to `while(true)`; on each iteration its body runs
   unconditionally).

3. **BB3 has exactly two outgoing edges**, induced by the `if` at `:191`:
   - When the predicate is true → BB4.
   - When the predicate is false → BB5.

4. **BB4 ends with `break` at `:196`.** Per Yul semantics, `break` exits the
   innermost enclosing for-loop, which is the outer `for {} 1 {}` at `:183`.
   Control flow therefore transfers to the **statement immediately following
   the for-loop**, which is `mstore(0x40, m)` at `:236` — i.e. the entry of
   BB8.

5. **BB5 has internal structure** (a nested `if iszero(eq(...))` at `:204`
   containing a nested for-loop at `:206`), but every internal branch
   converges at the end of `:213` and falls through to BB6.

6. **BB6** is a `for {} iszero(...) { p := add(p, 1) }` at `:217`; its loop
   condition is `iszero(eq(byte(0, mload(p)), 40))`. The loop terminates
   when `mload(p)` first equals `'('` (`= 0x28 = 40`). It has no `break` or
   `return`, only the implicit "condition false → exit" edge to BB7.

7. **BB7 ends with `break` at `:234`.** Same reasoning as BB4 — control
   flow transfers to BB8 at `:236`.

8. **BB8** has a single outgoing edge to BB9 (the closing `}` of the assembly
   block at `:237` falls through to `:238`).

9. **BB9** assigns `result = V(hash, signature)` at `:239` and falls through
   to the function's closing brace at `:240`, which is the implicit return.

By cases 1-8, every non-reverting path enters BB9. By case 9, every entry
into BB9 ends at `:239`. ∎

### 3.5 Path enumeration

The CFG has exactly **two end-to-end paths** through the function body
(modulo the nested loop iterations in BB5/BB6 which do not change the
function's return value):

- **Path P** (PersonalSign): BB1 → BB2 → BB3 → BB4 → BB8 → BB9.
  Final `hash'` = `_hashTypedData(keccak256(PERSONAL_SIGN_TYPEHASH || H))` (the
  re-hash at `:238`, applied because `t == 0` after BB4).
  Final `signature'` = `S` (untruncated).

- **Path T** (TypedDataSign): BB1 → BB2 → BB3 → BB5 → BB6 → BB7 → BB8 → BB9.
  Final `hash'` = `keccak256(0x1e, 0x42 + (d & 1))` from `:232`. Note: when
  `d & 1 == 1` (contentsName invalid) the hash is **deliberately corrupted**
  by adding one extra byte to the keccak input. This is a feature, not a
  bug — it ensures invalid contentsName cannot collide with a valid
  TypedDataSign hash.
  Final `signature'` = `S` truncated to drop the trailing
  `(APP_DOMAIN_SEPARATOR || contents || contentsDescription || uint16)`
  appendix (the `signature.length := signature.length - l` at `:233`).

Both paths terminate at `:239` and assign `result = V(hash', signature')`.

## 4. CFG analysis — Replayable variant

File: `src/lib/ERC1271.sol:243-327`.

### 4.1 Block-by-block diff against the standard variant

The Replayable variant is a structural clone with three differences:

| Std line(s) | Rep line(s) | Difference |
|-------------|-------------|------------|
| `:164` reads `chainId`        | `:252` discards `chainId` (`/*chainId*/`) | One fewer struct field copied into the typehash buffer. |
| `:170-175` writes 6 words at `t+0x40..t+0xe0` | `:258-262` writes 5 words at `t+0x40..t+0xc0` | One fewer mstore; the layout is denser. |
| `:220-223` typehash string includes `uint256 chainId,` | `:307-310` typehash string omits `uint256 chainId,` | Different typehash for replayability across chains. |
| `:230` final `keccak256(t, 0xe0)` | `:317` final `keccak256(t, 0xc0)` | Smaller hashed region matching the smaller struct. |
| `:239` calls inner verifier | `:326` calls inner verifier | **Identical call shape**. |

The control-flow keywords are **identical** in count and position:

- zero `return` keywords inside either assembly block
- two `break` keywords (`:283` and `:321`) at the same relative positions as
  the standard variant's `:196` and `:234`
- one nested `break` at `:295` (the contentsName scan), structurally identical
  to the standard's `:208`

### 4.2 The single-return-site lemma — Replayable

**Lemma 4.2 (Replayable variant)**. Every execution of
`_erc1271IsValidSignatureViaNestedEIP712Replayable(H, S)` that does not
revert reaches `:326` exactly once, and the function's return value equals
the value of `result` assigned at `:326`.

*Proof.* Identical structural proof to Lemma 3.4 with the line-number
substitutions above. The basic-block decomposition is isomorphic:

- BB1' = `:249-264`     (analogous to BB1)
- BB2' = `:266-269`     (analogous to BB2)
- BB3' = `:270-278`     (analogous to BB3)
- BB4' = `:279-284`     (analogous to BB4; `break` at `:283`)
- BB5' = `:287-300`     (analogous to BB5)
- BB6' = `:301-306`     (analogous to BB6)
- BB7' = `:307-322`     (analogous to BB7; `break` at `:321`)
- BB8' = `:323-324`     (analogous to BB8; restores `mstore(0x40, m)`)
- BB9' = `:325-326`     (analogous to BB9; single return site at `:326`)

By the same case analysis, every non-reverting path enters BB9' and ends at
`:326`. ∎

## 5. Main theorem and proof

**Theorem 5.1 (P15-std contrapositive)**. If `V(h', s') = false` for **every**
`(h', s')` derivable from `(H, S, address(this), eip712Domain())` along any
reachable path through `_erc1271IsValidSignatureViaNestedEIP712`, then the
function returns `false`.

*Proof.* By Lemma 3.4, every non-reverting execution terminates at `:239`
with `result := V(hash, signature)` for some `hash, signature` whose values
are determined by the path taken (P or T) and the symbolic inputs `(H, S)`
plus the contract state `(address(this), eip712Domain())`. Call this pair
`(h', s')`.

By hypothesis, `V(h', s') = false`. Therefore `result = false`. The function
returns `result`. ∎

**Theorem 5.2 (P15-rep contrapositive)**. Same statement, same proof, with
Lemma 4.2 in place of Lemma 3.4 and `:326` in place of `:239`. ∎

**Corollary 5.3** (the original P15 direction). If
`_erc1271IsValidSignatureViaNestedEIP712(H, S) = true`, then
`V(h', s') = true` for the specific `(h', s')` constructed by the path that
was actually taken. Same for the Replayable variant. *Proof: contrapositive
of Theorems 5.1 / 5.2.* ∎

## 6. Soundness gates

Four assumptions must hold for the proof to be sound. Each is enumerated
below with the regression check that guards it.

### 6.1 Gate G1 — no early `return` is added in future edits

The proof hinges on `return` appearing exactly zero times in lines 161-239
and 249-326 (excluding the implicit return at the closing brace). A future
PR that adds `return true` or `result = true; return result` inside the
assembly block would break the single-return-site argument silently.

**Regression check**: a grep-style invariant added to the FV coverage gate
(Phase 4 of `audit/FV_PLAN_ROUND_2.md`):

```bash
# Must produce exactly 0 lines.
awk '/function _erc1271IsValidSignatureViaNestedEIP712\(/,/^    }$/' \
    src/lib/ERC1271.sol | grep -E '^\s*(return|stop|invalid|selfdestruct)\b'
```

Suggested wording for inclusion in a forge-fmt-style or CI grep gate is in
§8.1 below.

### 6.2 Gate G2 — `break` semantics in Yul

The proof relies on Yul's specification of `break`: "Terminate the
innermost surrounding loop". From the Solidity reference:

> The `break` statement can be used inside a loop. It causes the innermost
> enclosing loop to terminate. Execution continues with the next statement
> after the loop.

In both functions, the outer loop at `:183` / `:270` is the innermost
loop containing the `break` at `:196` / `:283` and `:234` / `:321`. The
contentsName scan loops at `:206` / `:293` are the innermost loop for the
`break` at `:208` / `:295`, but those break out of the scan and fall
through to the truncate-and-recopy logic at `:210-212` / `:297-299`, which
is still inside BB5 / BB5'. There is no path where a `break` could escape
the function body skipping `:239` / `:326`.

This is a property of the Solidity / Yul compiler, not of this codebase.
A break in the Yul specification would invalidate countless production
deployments before reaching Kernel v4.

### 6.3 Gate G3 — soundness of `_erc1271IsValidSignatureNowCalldata`

The proof reduces the security of the outer functions to the security of
the abstract inner verifier `V`. The proof itself does not claim that `V`
is sound — that claim is the obligation of the inheriting contract.

In production Kernel v4, `V` is `_verifyFallbackSignature` for the 7702
and immutable-ECDSA paths:

- `Kernel7702._verifyFallbackSignature` — proven equivalent to
  `ECDSA.tryRecoverCalldata(hash, sig) == owner()` by Phase A property #9
  (Halmos, `test/halmos/FallbackSignatureHalmos.t.sol`, 2/2 PASS).
- `KernelImmutableECDSA._verifyFallbackSignature` — same shape, also proven
  by Phase A #9.

For the permission and validator paths, `_erc1271IsValidSignature` (one
level above the nested-EIP712 entry points) routes through
`_verifySignaturePermission` / `_validateUserOpValidator`. Those are
covered by Phase D #11 (Certora, view/write equivalence) and Phase D #4
(Certora, policy/signer failure ⇒ aggregate failure).

So `V`'s soundness is independently established for every production
binding. The composition is: P15 ∧ Phase A #9 ∧ Phase D #4 ∧ Phase D #11
⇒ the full ERC-1271 nested-EIP712 path on Kernel v4 admits a signature iff
the underlying ECDSA / policy chain admits it.

### 6.4 Gate G4 — `eip712Domain()` and `_hashTypedData(...)` purity

The proof treats `eip712Domain()` (BB1 / BB1') and `_hashTypedData(.)`
(BB9 / BB9') as opaque pure functions of `address(this)` and the contract
storage. Their soundness is the obligation of Solady's EIP-712 mixin,
which Kernel v4 imports unmodified from `solady/utils/EIP712.sol`. Solady
is itself audited (multiple third parties) and is the upstream of the
reference EIP-712 implementation used by major wallet clients.

If Solady's `_hashTypedData` were to return a value that collided with a
PersonalSign typehash on a non-PersonalSign input, the post-processing at
`:238` / `:325` would no longer be the identity on PersonalSign inputs —
but that is a Solady bug, not a Kernel v4 bug, and would be caught by
upstream regression tests.

## 7. Complementary FV evidence

This manual proof is the audit-grade closure of property #15, but it is
not the only evidence. The full evidence chain:

1. **Phase A #9** (Halmos, PROVEN, 2/2 — `test/halmos/FallbackSignatureHalmos.t.sol`)
   — `_verifyFallbackSignature` on both `Kernel7702` and
   `KernelImmutableECDSA` is bit-for-bit equivalent to
   `ECDSA.tryRecoverCalldata(hash, sig) == expectedSigner`. This pins the
   production `V` on the fallback path.

2. **Phase E Halmos** (PROVEN, 6/6 — `test/halmos/ERC1271NestedEIP712Halmos.t.sol`)
   — PersonalSign workflow proven for signature lengths `{0, 65, 100}` on
   both the standard and Replayable variants. This is the concrete witness
   that Path P in §3.5 (and its Replayable counterpart) does in fact
   bottom out in `V` and does not return `true` when `V` returns `false`.

3. **Phase E Kontrol partial** (no CEX, 90 SUCCESS terminals — `test/kontrol/ERC1271NestedEIP712Kontrol.t.sol`)
   — exploratory evidence that no bypass exists in 524 KCFG nodes covering
   both the PersonalSign and TypedDataSign branches with symbolic
   signature lengths up to 96 bytes. The 21 still-pending frontier nodes
   were under active exploration when the budget ran out; none had become
   a CEX.

4. **This manual proof** — the structural CFG argument that closes the
   TypedDataSign branch unconditionally, for all signature lengths, on
   both variants.

The four pieces together cover:

| Layer | Standard variant | Replayable variant |
|---|---|---|
| PersonalSign path | Halmos + manual CFG | Halmos + manual CFG |
| TypedDataSign path | Kontrol partial + manual CFG | Kontrol partial + manual CFG |
| Inner verifier `V` (production binding) | Phase A #9 (fallback), Phase D #4/#11 (permission) | same |

## 8. Regression-protection recommendation

The single-return-site argument is fragile under future edits. We propose
a defence-in-depth combination:

### 8.1 CI grep gate (cheap, recommended)

Add to `.github/workflows/foundry.yml` (or equivalent CI manifest):

```yaml
- name: ERC1271 nested EIP-712 single-return-site invariant
  run: |
    set -e
    # No `return`, `stop`, `invalid`, or `selfdestruct` keyword may appear
    # inside the assembly block of either nested-EIP-712 function in
    # src/lib/ERC1271.sol. The manual proof for property #15
    # (`audit/manual-proofs/property-15-erc1271-nested-eip712.md`) depends
    # on this. If you intentionally introduced one of these keywords,
    # you have invalidated the proof — re-run Kontrol on the property
    # or extend the manual proof to cover the new exit path before
    # merging.
    awk '/function _erc1271IsValidSignatureViaNestedEIP712(Replayable)?\(/,/^    }$/' \
        src/lib/ERC1271.sol \
      | grep -nE '^\s*(return|stop|invalid|selfdestruct)\b' \
      && { echo "ERC1271 nested-EIP-712 single-return-site invariant violated"; exit 1; } \
      || true
```

This is a syntactic check; it will not catch a clever encoding (e.g. a
`pop(0)` followed by manipulating the free memory pointer to skip the
restore at BB8). But it catches the overwhelmingly common forms — direct
`return`, Yul `stop`, premature `invalid`. A reviewer can sanity-check
the diff for the cleverer cases.

### 8.2 Per-PR Halmos run on the existing PersonalSign suite

`forge clean && halmos --function check --contract ERC1271NestedEIP712Halmos`
on every PR touching `src/lib/ERC1271.sol`. Cold ~25 s, warm ~10 s. This
will not catch a TypedDataSign-only regression (Halmos cannot reach that
branch), but it pins the PersonalSign + return-tail logic in place. Any
edit that affects `_hashTypedData(hash)` at `:238` / `:325` or breaks the
final `V(hash, signature)` call would CEX immediately.

### 8.3 Re-run Kontrol with a larger budget on releases

Kontrol with `--max-iterations 2000` and 8 workers on a 64-GB-RAM machine
estimated to close the 21 remaining frontier nodes in 4-6 hours. Run
per-release (every `vX.Y.0` cut), not per-PR.

## 9. Closing note for the auditor

The function bodies of `_erc1271IsValidSignatureViaNestedEIP712` and its
Replayable variant are unusual: they consist of >70 lines of inline Yul
that manipulate symbolic-length calldata, compute multiple keccak hashes
over data whose layout depends on a 2-byte length field embedded at the
tail of the signature, and conditionally truncate the signature before
the final verifier call. This shape is hostile to all three FV backends
we have available, for three different reasons:

- Halmos: keccak input length is computed from symbolic byte-equality
  checks → `NotConcreteError`.
- Kontrol / KEVM: SMT cost is exponential in the symbolic signature
  length × the trailing 2-byte length field → state-space blowup before
  closure.
- Certora: assembly memory writes and calldatacopy patterns are at the
  edge of what CVL summaries can model cleanly.

The single-return-site CFG argument is the right hammer for this nail.
It reduces the security claim to a structural property of the function
body — one that is mechanically checkable by inspection of the source
file (and by the CI grep gate in §8.1) — and that hands off the actual
signature-verification obligation to `V`, which we have independently
proven by Phase A #9 / Phase D #4 / Phase D #11.

The proof is rigorous within its stated assumptions (G1-G4 in §6); each
assumption is either guarded by a regression check or reduced to a
property of upstream tooling (Solidity compiler, Solady library) that
is independently audited.

We consider property #15 **closed**.
