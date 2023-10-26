# Kernel

Kernel is a smart contract account that is:

- Compatible with [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337).
- Modular (supports [plugins](./src/validator)).
- [Highly gas-efficient](https://github.com/zerodevapp/aa-benchmark).

Kernel is also a winner of [the inaugural Ethereum AA grant](https://erc4337.mirror.xyz/hRn_41cef8oKn44ZncN9pXvY3VID6LZOtpLlktXYtmA).  At the time of writing, [Kernel powers over 60% of all AA wallets](https://twitter.com/SixdegreeLab/status/1705585256638849325?s=20).

Kernel can be used as a standalone smart contract account, but most people use it through [ZeroDev](https://docs.zerodev.app/).

## Resources

- [Developing plugins](https://docs.zerodev.app/extend-wallets/overview)
- [Read the source code](https://github.com/zerodevapp/kernel)

## Build

Make sure [Foundry](https://github.com/foundry-rs/foundry) is installed.  Then:

```
forge install
forge build
forge test
```

## License

MIT

## Addresses

<details>
<summary>v2.2</summary>

| Name                 | Address                                    |
| -------------------- | ------------------------------------------ |
| Kernel               | 0x0DA6a956B9488eD4dd761E59f52FDc6c8068E6B5 |
| KernelLite           | 0xbEdb61Be086F3f15eE911Cc9AB3EEa945DEbFa96 |
</details>

<details>
<summary>v2.1</summary>

| Name                 | Address                                    |
| -------------------- | ------------------------------------------ |
| Kernel               | 0xf048AD83CB2dfd6037A43902a2A5Be04e53cd2Eb |
| KernelFactory        | 0x5de4839a76cf55d0c90e2061ef4386d962E15ae3 |
| ECDSA Validator      | 0xd9AB5096a832b9ce79914329DAEE236f8Eea0390 |
</details>

<details>
<summary>v2.0</summary>

| Name            | Address                                    |
| --------------- | ------------------------------------------ |
| Kernel          | 0xeB8206E02f6AB1884cfEa58CC7BabdA7d55aC957 |
| TempKernel      | 0x727A10897e70cd3Ab1a6e43d59A12ab0895A4995 |
| KernelFactory   | 0x12358cA00141D09cB90253F05a1DD16bE93A8EE6 |
| ECDSA Validator | 0x180D6465F921C7E0DEA0040107D342c87455fFF5 |
| ECDSA Factory   | 0xAf299A1f51560F51A1F3ADC0a5991Ac74b61b0BE |
</details>
