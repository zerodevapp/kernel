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
