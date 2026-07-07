# Kernel v4

ERC-4337 / ERC-7702 modular smart account with pluggable validation, execution, and hook modules. Implements [ERC-7579](https://eips.ethereum.org/EIPS/eip-7579) for standardized module interfaces.

## Key Features

### Modular Architecture (ERC-7579)

Six pluggable module types that can be installed and uninstalled at runtime:

| Type | Role |
|------|------|
| **Validator** | Validates UserOps and signatures — owns a nonce key namespace |
| **Executor** | Calls `executeFromExecutor` to perform actions on behalf of the account |
| **Fallback** | Extends the account with new function selectors (call or delegatecall) |
| **Hook** | Pre/post execution checks on validators, executors, and fallback selectors |
| **Policy** | Part of a permission — enforces rules (e.g. spending limits, target allowlists) |
| **Signer** | Part of a permission — provides the signature verification (e.g. passkey, multisig) |

### Permission System

Beyond simple validator modules, Kernel v4 supports **permissions** — a composition of one signer and one or more policies. This enables granular session keys: a dapp gets a signer that can only call specific selectors, under specific policies (spending caps, time windows, target restrictions), without touching the root validator.

### Three Account Variants

- **`KernelUUPS`** — UUPS upgradeable proxy. Standard deployment via `KernelFactory.deploy()`. Supports full module lifecycle and proxy upgrades via UserOp.
- **`KernelImmutableECDSA`** — ERC-1967 clone with an ECDSA fallback signer in immutable args. The fallback signer is fixed at deploy time, but users can `setRoot` to a different validator and the proxy is still UUPS-upgradeable. Deployed via `KernelFactory.deployECDSA()`.
- **`Kernel7702`** — EIP-7702 variant for EOA delegation. The EOA itself is the fallback signer (`ECDSA.recover == address(this)`). No initialization needed. Supports raw ERC-1271 signatures.

### Enable Mode

Install modules atomically with the first UserOp — no separate setup transaction. The UserOp nonce encodes an enable-mode flag; the signature carries both the install payload (with root validator approval) and the UserOp signature. Supports chain-specific and replayable (chain-agnostic) variants.

### Nonce-Encoded Validation

The 32-byte ERC-4337 nonce encodes which validator to use, giving each validator/permission its own nonce namespace. See [Data Encoding > UserOp Nonce](#userop-nonce) for the full layout.

### Hook System

Hooks provide pre/post execution checks. They bind to validators, executors, and fallback selectors independently:

- **Validator hook** — Runs around `executeUserOp` when a non-root validator with a hook is used
- **Executor hook** — Runs around `executeFromExecutor` for any installed executor
- **Fallback hook** — Runs around fallback selector dispatch

Two sentinel values: `address(0)` = not installed, `address(1)` = installed with no hook.

### Signature Verification (ERC-1271 / ERC-7739)

Three signature modes for `isValidSignature`:
1. **Raw** — Direct hash signing (only on `Kernel7702` where the EOA is the signer)
2. **Chain-specific nested EIP-712** — Wraps the hash in a `TypedDataSign` struct bound to chain ID
3. **Replayable nested EIP-712** — Same wrapping but without chain ID, valid across chains

All modes support both validator-based and permission-based signature verification, selected by the first 21 bytes of the signature.

### Standards

| Standard | Support |
|----------|---------|
| [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337) | Account abstraction via EntryPoint v0.9 |
| [ERC-7579](https://eips.ethereum.org/EIPS/eip-7579) | Modular smart account interfaces |
| [ERC-7702](https://eips.ethereum.org/EIPS/eip-7702) | EOA code delegation (`Kernel7702`) |
| [ERC-7739](https://eips.ethereum.org/EIPS/eip-7739) | Nested EIP-712 for safe `isValidSignature` |
| [ERC-7201](https://eips.ethereum.org/EIPS/eip-7201) | Namespaced storage for upgrade safety |
| [ERC-1271](https://eips.ethereum.org/EIPS/eip-1271) | Smart contract signature validation |

## Data Encoding

### UserOp Nonce

The 32-byte ERC-4337 nonce encodes the validation mode, type, and identifier:

```
| 1 byte  | 1 byte | 20 bytes | 2 bytes  | 8 bytes |
| vMode   | vType  | vId      | nonceKey | seq     |
```

**vMode** (ValidationMode flags):

| Value | Meaning |
|-------|---------|
| `0x00` | Standard — chain-specific, no inline install |
| `0x08` | Enable — install modules inline, chain-specific enable signature |
| `0x0C` | Enable + replayable enable signature |
| `0x40` | Replayable — chain-agnostic userOp hash |
| `0x48` | Enable + replayable userOp hash |
| `0x4C` | Enable + replayable enable signature + replayable userOp hash |

**vType** (ValidationType):

| Value | Meaning | vId contains |
|-------|---------|-------------|
| `0x00` | Root / Fallback | Ignored (uses stored root) |
| `0x01` | Validator | 20-byte validator address |
| `0x02` | Permission | 4-byte PermissionId (left-aligned, rest zero) |

**nonceKey + seq**: Each (vType, vId) combination has independent nonce namespaces via the nonceKey. The seq is incremented by the EntryPoint per standard ERC-4337 nonce management.

### UserOp Signature

#### Standard Mode (no enable flag)

For **validator** (vType=0x01 or root resolving to validator):

```
[raw signature bytes]
```

Passed directly to `IValidator.validateUserOp(userOp, userOpHash)`.

For **permission** (vType=0x02 or root resolving to permission):

```
abi.encode(PermissionSignature({
    signatures: [policy1Sig, policy2Sig, ..., signerSig]
}))
```

One signature per policy (in install order), plus one for the signer (last). Each policy's signature is passed to `IPolicy.checkUserOpPolicy`, and the signer's to `ISigner.checkUserOpSignature`.

#### Enable Mode (enable flag set in vMode)

```
abi.encode(EnableModeSignature({
    nonce: uint256,              // install nonce for replay protection
    packages: Install[],         // modules to install
    enableSignature: bytes,      // root validator's signature over the install digest
    userOpSignature: bytes       // the actual validation signature (standard or permission format)
}))
```

The install digest is:

```
EIP-712 hash of InstallPackages(uint256 nonce, Install[] packages)
```

If the enable-replayable flag (0x04) is set, the digest uses the chain-agnostic domain separator (no chainId).

### ERC-1271 Signature (`isValidSignature`)

After ERC-6492 unwrapping, the signature is parsed as:

```
| 1 byte | 1 byte | N bytes | remaining bytes       |
| vMode  | vType  | vId     | inner signature        |
```

Where N depends on vType:

| vType | N | vId content |
|-------|---|-------------|
| `0x00` (root) | 0 | Uses stored root, inner = `signature[2:]` |
| `0x01` (validator) | 20 | Validator address, inner = `signature[22:]` |
| `0x02` (permission) | 4 | PermissionId, inner = `signature[6:]` |

#### Standard Mode (no enable flag)

The inner signature is verified via `_verifySignature` against the installed validator or permission, same as UserOp standard mode.

#### Enable Mode for ERC-1271

Since `isValidSignature` is a `view` function, enable mode works differently than in UserOps — it **cannot** modify state (no module installation, no nonce increment). Instead it:

1. Verifies the install signature is valid (same digest as UserOp enable mode)
2. Checks the nonce is correct (view-only, no increment)
3. Uses **stateless** verification — finds the validator/permission modules inside the `packages` array and calls `IStatelessValidatorWithSender.validateSignatureWithDataWithSender` instead of the normal installed module

The inner signature format is the same `EnableModeSignature`:

```
abi.encode(EnableModeSignature({
    nonce: uint256,
    packages: Install[],
    enableSignature: bytes,       // root validator's signature over the install digest
    userOpSignature: bytes        // verified statelessly against modules in packages
}))
```

For permission-based enable mode, `userOpSignature` is a `PermissionSignature` — one signature per policy/signer found in the packages with the matching PermissionId.

> **Note:** vType cannot be root (`0x00`) in enable mode — it must specify an explicit validator or permission.

#### Nested EIP-712 Wrapping

The above describes the **validation layer** (which validator/permission to use). Independently, ERC-7739 wraps the `hash` before it reaches the validation layer:

**TypedDataSign** — The inner signature is:

```
[r | s | v | APP_DOMAIN_SEPARATOR (32 bytes) | contents (32 bytes) | contentsDescription | uint16(contentsDescription.length)]
```

**PersonalSign** — The inner signature is just `[r | s | v]`.

The replayable variant uses a `TypedDataSign` struct without `chainId` in the account domain.

### installModule / uninstallModule

```solidity
function installModule(uint256 moduleType, address module, bytes calldata initData) external payable;
function uninstallModule(uint256 moduleType, address module, bytes calldata initData) external payable;
```

`initData` is ABI-encoded as `InstallModuleDataFormat`:

```solidity
abi.encode(InstallModuleDataFormat({
    installData: bytes,    // forwarded to module's onInstall / onUninstall
    internalData: bytes    // kernel-internal configuration (format varies by type)
}))
```

#### internalData for Install

| Module Type | internalData format |
|-------------|---------------------|
| Validator (1) | `[bytes20 hookAddress][bytes4 selector₁][bytes4 selector₂]...` |
| Executor (2) | `[bytes20 hookAddress]` |
| Fallback (3) | `[bytes4 selector][bytes1 callType][bytes20 hookAddress]` |
| Hook (4) | Ignored (empty OK) |
| Policy (5) | `[bytes4 permissionId]` |
| Signer (6) | `[bytes4 permissionId][bytes20 hookAddress][bytes4 selector₁]...` |

**hookAddress** sentinel values:

| Address | Meaning |
|---------|---------|
| `address(0)` | Not installed / entry-point-only (for fallback: only EntryPoint can call) |
| `address(1)` | Installed with no hook |
| Other | Hook contract address (must be installed as hook module first) |

**callType** for fallback (type 3):

| Value | Meaning |
|-------|---------|
| `0x00` | `call` — regular call, appends `msg.sender` to calldata |
| `0xFF` | `delegatecall` — executes in Kernel's storage context |

#### internalData for Uninstall

| Module Type | internalData format |
|-------------|---------------------|
| Validator (1) | Ignored |
| Executor (2) | Ignored |
| Fallback (3) | `[bytes4 selector]` (first 4 bytes used) |
| Hook (4) | Ignored |
| Policy (5) | `[bytes4 permissionId]` — must uninstall in LIFO order (last installed first) |
| Signer (6) | `[bytes4 permissionId]` — all policies must be uninstalled first |

### Batch Install via `Install[]`

Three entry points for batch installation:

```solidity
// 1. During account creation — first package becomes root
initialize(Install[] calldata packages)

// 2. From EntryPoint or self
installModule(Install[] calldata packages)

// 3. With root validator signature (no EntryPoint needed)
installModule(bool replayable, uint256 nonce, Install[] calldata packages, bytes calldata signature)
```

Each `Install` struct:

```solidity
struct Install {
    uint256 moduleType;   // 1-6
    address module;       // module contract address
    bytes moduleData;     // forwarded to onInstall
    bytes internalData;   // kernel config (same format as table above)
}
```

**Permission install order**: When installing a permission, all policies (type 5) for that PermissionId must come first, followed by exactly one signer (type 6) with the same PermissionId. The signer finalizes the permission. Multiple permissions can be installed in a single batch — just ensure each permission's policies+signer are grouped together.

## Architecture

```
Kernel (abstract)
├── ModuleManager
│   ├── ValidationManager    — Validator/permission lifecycle, enable-mode, nonce mgmt
│   ├── ExecutorManager      — Executor install/uninstall with hook binding
│   ├── HookManager          — Hook install/uninstall, pre/post check dispatch
│   └── SelectorManager      — Fallback handler routing by function selector
├── ExecutionManager         — ERC-7579 execution modes (single/batch/delegatecall)
└── ERC1271                  — ERC-1271 / ERC-7739 signature verification

Concrete implementations:
├── KernelUUPS               — UUPS upgradeable proxy
├── KernelImmutableECDSA     — Minimal clone with immutable signer
└── Kernel7702               — EIP-7702 EOA delegation

Supporting contracts:
├── KernelFactory             — Deterministic ERC-1967 proxy deployment
└── Staker                    — EntryPoint staking and factory approval management
```

### Storage

All storage uses [ERC-7201](https://eips.ethereum.org/EIPS/eip-7201) namespaced slots to avoid collisions across modules and upgrades:

| Manager | Slot |
|---------|------|
| ValidationManager | `keccak256("kernel.v4.validation") - 1` |
| ModuleManager | `keccak256("kernel.v4.module") - 1` |
| ExecutorManager | `keccak256("kernel.v4.executor") - 1` |
| HookManager | `keccak256("kernel.v4.hook") - 1` |
| SelectorManager | `keccak256("kernel.v4.selector") - 1` |

## Project Structure

```
src/
├── Kernel.sol                  — Abstract base account
├── Kernel7702.sol              — EIP-7702 variant
├── KernelImmutableECDSA.sol    — Immutable ECDSA variant
├── KernelUUPS.sol              — UUPS upgradeable variant
├── KernelFactory.sol           — Deterministic proxy deployer
├── Staker.sol                  — EntryPoint staking manager
├── core/                       — Manager contracts
├── interfaces/                 — ERC-7579 interfaces
├── lib/                        — ERC1271, Lib4337, Utils
└── types/                      — Types, Constants, Errors, Structs

test/
├── btt/          — Branching Tree Technique tests (bulloak)
├── unit/         — Unit tests and gas benchmarks
├── integration/  — End-to-end integration tests
├── invariant/    — Invariant tests (1000 runs / 1000 depth)
├── fuzz/         — Fuzz tests
├── halmos/       — Symbolic execution (formal verification)
└── mock/         — Test mocks and helpers
```

## Getting Started

### Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation)
- [Soldeer](https://soldeer.xyz/) (dependency manager, bundled with Foundry)
- Solidity 0.8.33+

### Install

```sh
git clone git@github.com:zerodevapp/kernel_v4.git
cd kernel_v4
forge soldeer install
forge build
```

## Testing

```sh
# All tests
forge test

# BTT tests only
forge test --match-path "test/btt/*.t.sol"

# Unit tests only
forge test --match-path "test/unit/*.t.sol"

# Integration tests
forge test --match-path "test/integration/*.t.sol"

# Invariant tests
forge test --match-path "test/invariant/*.t.sol"

# Fuzz tests
forge test --match-path "test/fuzz/*.t.sol"

# Halmos (symbolic execution)
halmos
```

### Coverage

```sh
forge coverage \
  --no-match-coverage "(script|test|Foo|Bar|validator|sdk|signer)" \
  --report lcov

genhtml lcov.info \
  --output-directory coverage \
  --ignore-errors inconsistent \
  --ignore-errors corrupt

open coverage/index.html
```

## Dependencies

| Package | Version |
|---------|---------|
| [Solady](https://github.com/Vectorized/solady) | 0.1.26 |
| [account-abstraction](https://github.com/eth-infinitism/account-abstraction) | v0.9.0 |
| [OpenZeppelin Contracts](https://github.com/OpenZeppelin/openzeppelin-contracts) | 5.4.0 |
| [forge-std](https://github.com/foundry-rs/forge-std) | 1.11.0 |

## Configuration

Key settings in `foundry.toml`:

- **EVM version**: Prague (transient storage support)
- **Solc**: 0.8.33
- **Optimizer**: 200 runs
- **Invariant**: 1000 runs, 1000 depth

## License

MIT
