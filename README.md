# Patch Wallets

Patch Wallets is a wallet protocol that leverages EIP-4337 compliant smart contracts to provide a secure and convenient way for users to transact on Ethereum and EVM-compatible networks using their email, phone number, or social media accounts in a non-custodial manner. This repository contains the Kernel smart contracts source code for Patch Wallets.

## Resources

- [Docs](https://docs.patchwallet.com/projects/patch-wallets)
- [Code](https://github.com/PaymagicXYZ/kernel)

## Introduction

Patch Wallets allow users to transact on the Ethereum network using their email, phone number, or social media accounts, eliminating the need for private keys or custodians. The protocol uses the EIP-4337 compatible Kernel contracts with the same deterministic address deployed to all EVM chains. Each wallet is attached to the email, phone number, or social media account of the user and transaction signing can be done through any signing service, although we recommend Lit Protocol.

## Getting Started

### Prerequisites

Ensure [Foundry](https://github.com/foundry-rs/foundry) is installed.

### Build

To build the project, run the following commands:

```bash
forge install
forge build
forge test
```

## Deploy

### Test Contracts

First runs simulation, giving gas costs.

```bash
forge script scripts/DeployKernelMultiTest.s.sol --sig "run(bytes32 salt)" "0x1" --fork-url <RPC_URL>
```

Actually broadcasts deploy and setup txs to the network

```bash
forge script scripts/DeployKernelMultiTest.s.sol --sig "run(bytes32 salt)" "0x1" --fork-url <RPC_URL> --broadcast
```

This deploys contracts to following deterministic addresses:

- MultiECDSAValidatorNew: 0x3153652fAC4454b9Ae847d38F607aE78731902C9
- MultiECDSAFactoryPatch: 0xA39A072E0330f940C10496546125B5e6a3B4B811

### Production Contracts

First runs simulation, giving gas costs.

```bash
forge script scripts/DeployKernelMultiProd.s.sol --sig "run(bytes32 salt)" "0x2" --fork-url <RPC_URL>
```

Actually broadcasts deploy and setup txs to the network

```bash
forge script scripts/DeployKernelMultiProd.s.sol --sig "run(bytes32 salt)" "0x2" --fork-url <RPC_URL> --broadcast
```

This deploys contracts to following deterministic addresses:

- MultiECDSAValidatorNew: 0x9392C6a8A0b5d49cc697B8242d477509bAE16700
- MultiECDSAFactoryPatch: 0x33DDF684dcc6937FfE59D8405aA80c41fB518C5c
