# Kernel

Kernel is a smart contract account that is:

- Compatible with [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337).
- Modular (supports [ERC-7579 plugins](https://eips.ethereum.org/EIPS/eip-7579)).
- [Highly gas-efficient](https://github.com/zerodevapp/aa-benchmark).

Kernel is also a winner of [the inaugural Ethereum AA grant](https://erc4337.mirror.xyz/hRn_41cef8oKn44ZncN9pXvY3VID6LZOtpLlktXYtmA).  At the time of writing, [Kernel is the most widely used modular smart account.](https://www.bundlebear.com).

## SDKs

Kernel is supported by all major AA SDKs, including:

- [ZeroDev](https://docs.zerodev.app/)
- [Viem](https://viem.sh/account-abstraction/accounts/smart/toEcdsaKernelSmartAccount)
- [Permissionless.js](https://docs.pimlico.io/permissionless/how-to/accounts/use-kernel-account)

## Plugins

- Read more about [Kernel's permissions system](https://docs.zerodev.app/sdk/permissions/intro) and learn to build your own plugins.
- For officially maintained plugins, some live in [this repo](https://github.com/zerodevapp/kernel-7579-plugins/tree/master), and the rest live in [`/src`](/src).

## Build

Make sure [Foundry](https://github.com/foundry-rs/foundry) is installed.  Then:

```
forge install
forge build
forge test
```

### Deployment

We have built a [portal](https://kernel.zerodev.app/) for deploying Kernel on any network.

If you don't see a network, feel free to open an issue or use manual connection.

## License

MIT

## Addresses
<details>
<summary>v3.3</summary>

| Name                 | Address                                    |
| -------------------- | ------------------------------------------ |
| Meta Factory         | [0xd703aaE79538628d27099B8c4f621bE4CCd142d5](https://contractscan.xyz/contract/0xd703aae79538628d27099b8c4f621be4ccd142d5) |
| Factory              | [0x2577507b78c2008Ff367261CB6285d44ba5eF2E9](https://contractscan.xyz/contract/0x2577507b78c2008Ff367261CB6285d44ba5eF2E9) |
| Kernel               | [0xd6CEDDe84be40893d153Be9d467CD6aD37875b28](https://contractscan.xyz/contract/0xd6CEDDe84be40893d153Be9d467CD6aD37875b28) |

</details>


<details>
<summary>v3.2</summary>

| Name                 | Address                                    |
| -------------------- | ------------------------------------------ |
| Meta Factory         | [0xd703aaE79538628d27099B8c4f621bE4CCd142d5](https://contractscan.xyz/contract/0xd703aae79538628d27099b8c4f621be4ccd142d5) |
| Factory              | [0x7a1dBAB750f12a90EB1B60D2Ae3aD17D4D81EfFe](https://contractscan.xyz/contract/0x7a1dBAB750f12a90EB1B60D2Ae3aD17D4D81EfFe) |
| Kernel               | [0xD830D15D3dc0C269F3dBAa0F3e8626d33CFdaBe1](https://contractscan.xyz/contract/0xD830D15D3dc0C269F3dBAa0F3e8626d33CFdaBe1) |

</details>

<details>
<summary>v3.1</summary>

| Name                 | Address                                    |
| -------------------- | ------------------------------------------ |
| Meta Factory         | [0xd703aaE79538628d27099B8c4f621bE4CCd142d5](https://contractscan.xyz/contract/0xd703aae79538628d27099b8c4f621be4ccd142d5) |
| Factory              | [0xaac5D4240AF87249B3f71BC8E4A2cae074A3E419](https://contractscan.xyz/contract/0xaac5d4240af87249b3f71bc8e4a2cae074a3e419) |
| Kernel               | [0xBAC849bB641841b44E965fB01A4Bf5F074f84b4D](https://contractscan.xyz/contract/0xbac849bb641841b44e965fb01a4bf5f074f84b4d) |
| ECDSA Validator      | [0x845ADb2C711129d4f3966735eD98a9F09fC4cE57](https://contractscan.xyz/contract/0x845adb2c711129d4f3966735ed98a9f09fc4ce57) |

</details>

<details>
<summary>v3.0</summary>

| Name                 | Address                                    |
| -------------------- | ------------------------------------------ |
| Meta Factory         | [0xd703aaE79538628d27099B8c4f621bE4CCd142d5](https://contractscan.xyz/contract/0xd703aae79538628d27099b8c4f621be4ccd142d5) |
| Factory              | [0x6723b44Abeec4E71eBE3232BD5B455805baDD22f](https://contractscan.xyz/contract/0x6723b44abeec4e71ebe3232bd5b455805badd22f) |
| Kernel               | [0x94F097E1ebEB4ecA3AAE54cabb08905B239A7D27](https://contractscan.xyz/contract/0x94f097e1ebeb4eca3aae54cabb08905b239a7d27) |
| ECDSA Validator      | [0x8104e3Ad430EA6d354d013A6789fDFc71E671c43](https://contractscan.xyz/contract/0x8104e3ad430ea6d354d013a6789fdfc71e671c43) |

</details>

<details>
<summary>v2.4</summary>

| Name                 | Address                                    |
| -------------------- | ------------------------------------------ |
| Kernel               | [0xd3082872F8B06073A021b4602e022d5A070d7cfC](https://contractscan.xyz/contract/0xd3082872f8b06073a021b4602e022d5a070d7cfc) |
| KernelFactory        | [0x5de4839a76cf55d0c90e2061ef4386d962E15ae3](https://contractscan.xyz/contract/0x5de4839a76cf55d0c90e2061ef4386d962e15ae3) |
| SessionKeyValidator  | [0x5C06CE2b673fD5E6e56076e40DD46aB67f5a72A5](https://contractscan.xyz/contract/0x5c06ce2b673fd5e6e56076e40dd46ab67f5a72a5) |
| ECDSA Validator      | [0xd9AB5096a832b9ce79914329DAEE236f8Eea0390](https://contractscan.xyz/contract/0xd9ab5096a832b9ce79914329daee236f8eea0390) |
</details>

<details>
<summary>v2.3</summary>

| Name                 | Address                                    |
| -------------------- | ------------------------------------------ |
| Kernel               | [0xD3F582F6B4814E989Ee8E96bc3175320B5A540ab](https://contractscan.xyz/contract/0xd3f582f6b4814e989ee8e96bc3175320b5a540ab) |
| KernelFactory        | [0x5de4839a76cf55d0c90e2061ef4386d962E15ae3](https://contractscan.xyz/contract/0x5de4839a76cf55d0c90e2061ef4386d962e15ae3) |
| KernelLite           | [0x482EC42E88a781485E1B6A4f07a0C5479d183291](https://contractscan.xyz/contract/0x482ec42e88a781485e1b6a4f07a0c5479d183291) |
| SessionKeyValidator  | [0x5C06CE2b673fD5E6e56076e40DD46aB67f5a72A5](https://contractscan.xyz/contract/0x5c06ce2b673fd5e6e56076e40dd46ab67f5a72a5) |
| ECDSA Validator      | [0xd9AB5096a832b9ce79914329DAEE236f8Eea0390](https://contractscan.xyz/contract/0xd9ab5096a832b9ce79914329daee236f8eea0390) |
</details>

<details>
<summary>v2.2</summary>

| Name                 | Address                                    |
| -------------------- | ------------------------------------------ |
| Kernel               | [0x0DA6a956B9488eD4dd761E59f52FDc6c8068E6B5](https://contractscan.xyz/contract/0x0da6a956b9488ed4dd761e59f52fdc6c8068e6b5) |
| KernelFactory        | [0x5de4839a76cf55d0c90e2061ef4386d962E15ae3](https://contractscan.xyz/contract/0x5de4839a76cf55d0c90e2061ef4386d962e15ae3) |
| KernelLite           | [0xbEdb61Be086F3f15eE911Cc9AB3EEa945DEbFa96](https://contractscan.xyz/contract/0xbedb61be086f3f15ee911cc9ab3eea945debfa96) |
| SessionKeyValidator  | [0x5C06CE2b673fD5E6e56076e40DD46aB67f5a72A5](https://contractscan.xyz/contract/0x5c06ce2b673fd5e6e56076e40dd46ab67f5a72a5) |
| ECDSA Validator      | [0xd9AB5096a832b9ce79914329DAEE236f8Eea0390](https://contractscan.xyz/contract/0xd9ab5096a832b9ce79914329daee236f8eea0390) |

</details>

<details>
<summary>v2.1</summary>

| Name                 | Address                                    |
| -------------------- | ------------------------------------------ |
| Kernel               | [0xf048AD83CB2dfd6037A43902a2A5Be04e53cd2Eb](https://contractscan.xyz/contract/0xf048ad83cb2dfd6037a43902a2a5be04e53cd2eb) |
| KernelFactory        | [0x5de4839a76cf55d0c90e2061ef4386d962E15ae3](https://contractscan.xyz/contract/0x5de4839a76cf55d0c90e2061ef4386d962e15ae3) |
| SessionKeyValidator  | [0x5C06CE2b673fD5E6e56076e40DD46aB67f5a72A5](https://contractscan.xyz/contract/0x5c06ce2b673fd5e6e56076e40dd46ab67f5a72a5) |
| ECDSA Validator      | [0xd9AB5096a832b9ce79914329DAEE236f8Eea0390](https://contractscan.xyz/contract/0xd9ab5096a832b9ce79914329daee236f8eea0390) |
</details>

<details>
<summary>v2.0</summary>

| Name            | Address                                    |
| --------------- | ------------------------------------------ |
| Kernel          | [0xeB8206E02f6AB1884cfEa58CC7BabdA7d55aC957](https://contractscan.xyz/contract/0xeb8206e02f6ab1884cfea58cc7babda7d55ac957) |
| TempKernel      | [0x727A10897e70cd3Ab1a6e43d59A12ab0895A4995](https://contractscan.xyz/contract/0x727a10897e70cd3ab1a6e43d59a12ab0895a4995) |
| KernelFactory   | [0x12358cA00141D09cB90253F05a1DD16bE93A8EE6](https://contractscan.xyz/contract/0x12358ca00141d09cb90253f05a1dd16be93a8ee6) |
| ECDSA Validator | [0x180D6465F921C7E0DEA0040107D342c87455fFF5](https://contractscan.xyz/contract/0x180d6465f921c7e0dea0040107d342c87455fff5) |
| ECDSA Factory   | [0xAf299A1f51560F51A1F3ADC0a5991Ac74b61b0BE](https://contractscan.xyz/contract/0xaf299a1f51560f51a1f3adc0a5991ac74b61b0be) |
</details>
