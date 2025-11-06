# Kernel v4 Audit Changelog

**Commit Range:** `ff20f6c` to `25e51e1` (HEAD)
**Date Range:** October 14, 2025 - October 22, 2025
**Files Changed:** 21 files in `src/` (+625, -500 lines)

---

## Added Features

### Staker Contract (`src/Staker.sol`) - NEW
Factory staking management contract for ERC-4337 EntryPoint compliance.
- Factory approval whitelist (owner-controlled or EIP-712 signature-based)
- EntryPoint stake/unstake/withdraw functions
- `deployWithFactory()` - Deploy accounts through approved factories
- `approveFactory()` - Owner approves/disapproves factory
- `approveFactoryWithSignature()` - EIP-712 signature-based approval (chain-agnostic)
- **Commits:** e4431db, 52265ac
- **PR:** #20

### Enable Mode Signature Support
Added support for installing modules via signature in UserOp flow (enable mode).
- Allows users to install validators/modules atomically with their first UserOp
- Uses `EnableModeSignature` struct containing: nonce, packages to install, enable signature, and userOp signature
- EIP-712 signature verification with nonce replay protection
- Nonce is checked and incremented to prevent replay attacks
- **Files:** `src/Kernel.sol` (validateUserOp), `src/core/ModuleManager.sol`
- **Commits:** 7a578c2
- **PR:** #25

### Root Validator Replacement
New `setRoot()` overload allows replacing root validator with automatic cleanup of previous root.
- **Function:** `setRoot(Install[] calldata pkg, bool removeCurrent, bytes calldata uninstallData)`
- Supports uninstalling validators and permissions (including policies and signers)
- Calls `onUninstall()` on removed modules
- **Commits:** a691aad, f646dec, ffe4d58
- **PR:** #7

### Validator/Permission Management Functions
New internal functions for module lifecycle management:
- `_uninstallValidator()` - Uninstall validator with ValidationInfo cleanup
- `_uninstallPolicyWithVid()` - Remove policy from specific permission
- `_uninstallSignerWithVid()` - Remove signer from specific permission
- **Files:** `src/core/ModuleManager.sol`, `src/core/ValidationManager.sol`
- **Commits:** a691aad

### ValidationId Utility Functions
Helper functions for ValidationId type extraction and creation in `lib/Utils.sol`:
- `parseNonce()` - Extract validation mode, type, and ID from nonce (moved from ValidationManager)
- `getType()` - Extract validation type from ValidationId
- `getValidator()` - Extract validator address from ValidationId
- `validatorToIdentifier()` - Create ValidationId from validator address
- `permissionToIdentifier()` - Create ValidationId from PermissionId
- `isPermissionType()` - Check if validation type is permission variant
- `calldataKeccak()` - Efficient calldata hashing for EIP-712
- **Commits:** 5ee7a26, b6e1ee4, f67e36c, 6e3a5f5
- **PR:** #19

### ERC-1271 Raw Hash Signing
Support for raw hash signing in EIP-7702 accounts (without EIP-712 wrapping).
- **Hook:** `_erc1271RawAllowed()` - Override to enable raw signing
- Enabled by default in `Kernel7702` contract
- **Files:** `src/Kernel7702.sol`, `src/lib/ERC1271.sol`
- **Commits:** 40b0ff6, 83d6e32, 776fe04, 8999222
- **PR:** #24

---

## Changed Features

### ValidationId Encoding (BREAKING CHANGE)
ValidationId changed from 20 bytes to 21 bytes to embed validation type in first byte.
- **Before:** `bytes20` (address only)
- **After:** `bytes21` (1 byte type + 20 bytes address/permissionId)
- **Encoding:** Byte 0 = ValidationType (ROOT=0, VALIDATOR=1, PERMISSION=2), Bytes 1-21 = address/permissionId
- **Impact:** Type checking no longer requires storage reads, eliminates `vType` field from ValidationInfo struct
- **Migration:** Use `validatorToIdentifier()` and `permissionToIdentifier()` utility functions
- **Storage Optimization:** Removed `vType` field from ValidationInfo struct
- **Commits:** 5ee7a26, b6e1ee4, f67e36c, 6e3a5f5
- **PR:** #19

### Initialization Pattern Refactor
- `Kernel.initialize()` is now `virtual` and `payable` - implementation moved to derived contracts
- `KernelUUPS.initialize()` has `initializer` modifier and properly initializes in constructor
- `KernelUUPS` constructor calls `_disableInitializers()` to prevent implementation initialization
- `Kernel7702.initialize()` is NO-OP (stateless accounts don't need initialization)
- `KernelImmutableECDSA._initialize()` removed `initializer` modifier (protection at UUPS level)
- **Files:** `src/Kernel.sol`, `src/KernelUUPS.sol`, `src/Kernel7702.sol`, `src/KernelImmutableECDSA.sol`
- **Commits:** 75e788b, 69e12fb, 041bb87, a8cec2c
- **PR:** #17

### Factory Deployment Protection
Factory now checks if account is already deployed before calling initialize.
- Prevents re-initialization of already deployed accounts
- **Files:** `src/KernelFactory.sol`
- **Functions:** `deployImmutableECDSA()`, `deployImmutableECDSAWithExtraCall()`
- **Commits:** 75e788b
- **PR:** #17

### Factory Salt Calculation Optimization
Optimized to use `EfficientHashLib` instead of `keccak256(abi.encode())`.
- **File:** `src/KernelFactory.sol`
- **Function:** `_calculateSalt()` - NEW internal function using EfficientHashLib
- **Commits:** e4431db

### Executor Authorization Check
Added installation verification in `executeFromExecutor()` flow via `executorHook` modifier.
- **Change:** Added `require(address(hook) != address(0), Unauthorized())` in `executorHook` modifier
- Prevents uninstalled executors from executing transactions
- **File:** `src/core/ModuleManager.sol`
- **Commits:** 7f55374, eff6542, dcec72e
- **PR:** #18

### Module Type Validation
`supportsModule()` now returns false for moduleTypeId == 0 (invalid/undefined type).
- **File:** `src/Kernel.sol`
- **Commits:** 73a61ed
- **PR:** #13

### Enable Mode Nonce Replay Protection
Added nonce check and increment in `validateUserOp()` enable mode flow.
- **Change:** Added `_checkAndIncrementNonce(sig.nonce)` after signature verification
- Prevents signature replay attacks
- **File:** `src/Kernel.sol`
- **Commits:** 7a578c2
- **PR:** #25

### Hook Validation Logic Enhancement
Optimized hook validation check in UserOp flow.
- **Change:** Reordered conditional logic for gas optimization (root or hookless paths first)
- **File:** `src/Kernel.sol`
- **Commits:** fa6a1bd, cdf738b
- **PR:** #22

### Signature Verification Optimization
Use `ECDSA.tryRecoverCalldata()` instead of `ECDSA.tryRecover()` when signature is in calldata.
- **Files:** `src/KernelImmutableECDSA.sol`, `src/Kernel7702.sol`
- **Impact:** Gas savings for signature verification

### Access Control Modifier Optimization
Changed `_onlyEntryPointOrSelf()` and `_authorizeUpgrade()` to `view` functions.
- Prevents accidental state changes in authorization checks
- **Files:** `src/Kernel.sol`, `src/KernelUUPS.sol`

---

## Removed Features

### KernelHelper.sol - DELETED
EIP-712 digest generation moved inline to `ModuleManager.sol`.
- Reduces external dependencies
- Functions moved: `installDigest()`, `_installHash()`, `_hashTypedData()`, `_hashTypedDataSansChainId()`
- Now implemented as internal functions in ModuleManager

### Removed Functions
- `ExecutorManager.installAndExecute()` - Removed unused and potentially dangerous function
- `KernelImmutableECDSA._statelessInitializeCheck()` - Removed unused hook
- `KernelImmutableECDSA` EthSign prefix handling - Simplified to use only standard ECDSA recovery
- **Commits:** 35f65fe
