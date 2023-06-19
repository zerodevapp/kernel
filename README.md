# Kernel

Kernel is a minimal smart contract account designed to be extended.

- [Docs](https://docs.zerodev.app/extend-wallets/overview)
- [Code](https://github.com/zerodevapp/kernel)

## Build

Make sure [Foundry](https://github.com/foundry-rs/foundry) is installed. Then:

```
forge install
forge build
forge test
```

## Deploy

Make sure [Foundry](https://github.com/foundry-rs/foundry) is installed. Then:

Staging/Production:

First runs simulation, giving gas costs.

```
forge script scripts/DeployKernelMultiProd.s.sol --sig "run(bytes32 salt)" "0x5061746368" --fork-url <RPC_URL>
```

Actually broadcasts deploy and setup txs to the network

```
forge script scripts/DeployKernelMultiProd.s.sol --sig "run(bytes32 salt)" "0x5061746368" --fork-url <RPC_URL> --broadcast
```

Test:

First runs simulation, giving gas costs.

```
forge script scripts/DeployKernelMultiTest.s.sol --sig "run(bytes32 salt)" "0xa" --fork-url <RPC_URL>
```

Actually broadcasts deploy and setup txs to the network

```
forge script scripts/DeployKernelMultiTest.s.sol --sig "run(bytes32 salt)" "0xa" --fork-url <RPC_URL> --broadcast
```
