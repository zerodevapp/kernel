/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */
import { Signer, utils, Contract, ContractFactory, Overrides } from "ethers";
import type { Provider, TransactionRequest } from "@ethersproject/providers";
import type { PromiseOrValue } from "../common";
import type { KernelStorage, KernelStorageInterface } from "../KernelStorage";

const _abi = [
  {
    inputs: [
      {
        internalType: "contract IEntryPoint",
        name: "_entryPoint",
        type: "address",
      },
    ],
    stateMutability: "nonpayable",
    type: "constructor",
  },
  {
    inputs: [],
    name: "AlreadyInitialized",
    type: "error",
  },
  {
    inputs: [],
    name: "NotAuthorizedCaller",
    type: "error",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "oldValidator",
        type: "address",
      },
      {
        indexed: true,
        internalType: "address",
        name: "newValidator",
        type: "address",
      },
    ],
    name: "DefaultValidatorChanged",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "bytes4",
        name: "selector",
        type: "bytes4",
      },
      {
        indexed: true,
        internalType: "address",
        name: "executor",
        type: "address",
      },
      {
        indexed: true,
        internalType: "address",
        name: "validator",
        type: "address",
      },
    ],
    name: "ExecutionChanged",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "newImplementation",
        type: "address",
      },
    ],
    name: "Upgraded",
    type: "event",
  },
  {
    inputs: [
      {
        internalType: "bytes4",
        name: "_disableFlag",
        type: "bytes4",
      },
    ],
    name: "disableMode",
    outputs: [],
    stateMutability: "payable",
    type: "function",
  },
  {
    inputs: [],
    name: "entryPoint",
    outputs: [
      {
        internalType: "contract IEntryPoint",
        name: "",
        type: "address",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "getDefaultValidator",
    outputs: [
      {
        internalType: "contract IKernelValidator",
        name: "validator",
        type: "address",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "getDisabledMode",
    outputs: [
      {
        internalType: "bytes4",
        name: "disabled",
        type: "bytes4",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes4",
        name: "_selector",
        type: "bytes4",
      },
    ],
    name: "getExecution",
    outputs: [
      {
        components: [
          {
            internalType: "ValidAfter",
            name: "validAfter",
            type: "uint48",
          },
          {
            internalType: "ValidUntil",
            name: "validUntil",
            type: "uint48",
          },
          {
            internalType: "address",
            name: "executor",
            type: "address",
          },
          {
            internalType: "contract IKernelValidator",
            name: "validator",
            type: "address",
          },
        ],
        internalType: "struct ExecutionDetail",
        name: "",
        type: "tuple",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "getLastDisabledTime",
    outputs: [
      {
        internalType: "uint48",
        name: "",
        type: "uint48",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "uint192",
        name: "key",
        type: "uint192",
      },
    ],
    name: "getNonce",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "getNonce",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "contract IKernelValidator",
        name: "_defaultValidator",
        type: "address",
      },
      {
        internalType: "bytes",
        name: "_data",
        type: "bytes",
      },
    ],
    name: "initialize",
    outputs: [],
    stateMutability: "payable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "contract IKernelValidator",
        name: "_defaultValidator",
        type: "address",
      },
      {
        internalType: "bytes",
        name: "_data",
        type: "bytes",
      },
    ],
    name: "setDefaultValidator",
    outputs: [],
    stateMutability: "payable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes4",
        name: "_selector",
        type: "bytes4",
      },
      {
        internalType: "address",
        name: "_executor",
        type: "address",
      },
      {
        internalType: "contract IKernelValidator",
        name: "_validator",
        type: "address",
      },
      {
        internalType: "uint48",
        name: "_validUntil",
        type: "uint48",
      },
      {
        internalType: "uint48",
        name: "_validAfter",
        type: "uint48",
      },
      {
        internalType: "bytes",
        name: "_enableData",
        type: "bytes",
      },
    ],
    name: "setExecution",
    outputs: [],
    stateMutability: "payable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "_newImplementation",
        type: "address",
      },
    ],
    name: "upgradeTo",
    outputs: [],
    stateMutability: "payable",
    type: "function",
  },
] as const;

const _bytecode =
  "0x60a0346100d257601f610b2138819003918201601f19168301916001600160401b038311848410176100d7578084926020946040528339810103126100d257516001600160a01b03811681036100d2576080527f439ffe7df606b78489639bc0b827913bd09e1246fa6802968a5b3694c53e0dd98054600160501b600160f01b0319166a0100000000000000000000179055604051610a3390816100ee823960805181818160bf0152818161022b015281816102c90152818161038001528181610556015281816105f901526107000152f35b600080fd5b634e487b7160e01b600052604160045260246000fdfe6080604081815260048036101561001557600080fd5b600092833560e01c9081630b3dc354146108775750806329f8b1741461067b5780633659cfe6146105d25780633e1b08121461050c57806351166ba01461043a57806355b14f501461036557806357b750471461032d57806388e7fd06146102f8578063b0d691fe146102b4578063d087d288146101f5578063d1f578941461014b5763d5416221146100a757600080fd5b6020366003190112610147576100bb6108ac565b91337f00000000000000000000000000000000000000000000000000000000000000006001600160a01b031614158061013d575b610130575050600080516020610a1383398151915290815469ffffffffffff000000004260201b169160e01c9069ffffffffffffffffffff19161717905580f35b51637046c88d60e01b8152fd5b50303314156100ef565b8280fd5b508290610157366108f1565b600080516020610a13833981519152549295919391926001600160a01b039060501c81166101e6578661018a87986109c5565b16803b156101e2576101b39486809486519788958694859363064acaab60e11b8552840161099d565b03925af19081156101d957506101c65750f35b6101cf90610967565b6101d65780f35b80fd5b513d84823e3d90fd5b8580fd5b835162dc149f60e41b81528390fd5b509190346102b057816003193601126102b0578051631aab3f0d60e11b81523093810193909352602483018290526020836044817f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03165afa9182156102a5579161026c575b6020925051908152f35b90506020823d821161029d575b816102866020938361097b565b81010312610298576020915190610262565b600080fd5b3d9150610279565b9051903d90823e3d90fd5b5080fd5b5050346102b057816003193601126102b057517f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03168152602090f35b5050346102b057816003193601126102b057600080516020610a13833981519152549051602091821c65ffffffffffff168152f35b5050346102b057816003193601126102b057602090600080516020610a138339815191525460e01b90519063ffffffff60e01b168152f35b509190610371366108f1565b919291906001600160a01b03337f00000000000000000000000000000000000000000000000000000000000000008216141580610430575b6104205795868697600080516020610a138339815191525460501c16956103cf816109c5565b1690818551967fa35f5cdc5fbabb614b4cd5064ce5543f43dc8fab0e4da41255230eb8aba2531c8980a3813b1561041c5786866101b382968296839563064acaab60e11b8552840161099d565b8680fd5b8351637046c88d60e01b81528790fd5b50303314156103a9565b5050346102b05760203660031901126102b05760018160809361045b6108ac565b816060845161046981610935565b8281528260208201528286820152015263ffffffff60e01b1681527f439ffe7df606b78489639bc0b827913bd09e1246fa6802968a5b3694c53e0dda60205220918051906104b682610935565b83549365ffffffffffff948581169586855260208501818360301c1681528486019260601c83526060878060a01b0380988196015416960195865284519788525116602087015251169084015251166060820152f35b509190346102b057602092836003193601126101475780356001600160c01b038116908190036105ce578251631aab3f0d60e11b81523092810192909252602482015283816044817f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03165afa9283156105c35792610594575b5051908152f35b9091508281813d83116105bc575b6105ac818361097b565b810103126102985751903861058d565b503d6105a2565b8251903d90823e3d90fd5b8380fd5b506020366003190112610147576001600160a01b03813581811693909291848403610298577f00000000000000000000000000000000000000000000000000000000000000001633141580610671575b6101305750507f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc557fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b8280a280f35b5030331415610622565b5060c0366003190112610147576106906108ac565b916001600160a01b03602435818116939192908490036101e2576044359483861680960361041c576064359265ffffffffffff948585168095036108735760843586811680910361086f5760a43567ffffffffffffffff811161086b576106fa90369085016108c3565b969094837f00000000000000000000000000000000000000000000000000000000000000001633141580610861575b610851578a928a8d979695936bffffffffffff0000000000006001948b519461075186610935565b8552602085019283528b85019384526060850197885263ffffffff60e01b169c8d8b527f439ffe7df606b78489639bc0b827913bd09e1246fa6802968a5b3694c53e0dda6020528b8b20945116915160301b16916bffffffffffffffffffffffff19905160601b169117178155019151166bffffffffffffffffffffffff60a01b825416179055873b15610147576107fa8451958693849363064acaab60e11b8552840161099d565b038183895af19081156108485750610835575b507fed03d2572564284398470d3f266a693e29ddfff3eba45fc06c5e91013d3213538480a480f35b61084190949194610967565b923861080d565b513d87823e3d90fd5b8651637046c88d60e01b81528590fd5b5030331415610729565b8a80fd5b8980fd5b8880fd5b8490346102b057816003193601126102b057600080516020610a138339815191525460501c6001600160a01b03168152602090f35b600435906001600160e01b03198216820361029857565b9181601f840112156102985782359167ffffffffffffffff8311610298576020838186019501011161029857565b906040600319830112610298576004356001600160a01b038116810361029857916024359067ffffffffffffffff821161029857610931916004016108c3565b9091565b6080810190811067ffffffffffffffff82111761095157604052565b634e487b7160e01b600052604160045260246000fd5b67ffffffffffffffff811161095157604052565b90601f8019910116810190811067ffffffffffffffff82111761095157604052565b90918060409360208452816020850152848401376000828201840152601f01601f1916010190565b600080516020610a1383398151915280547fffff0000000000000000000000000000000000000000ffffffffffffffffffff1660509290921b600160501b600160f01b031691909117905556fe439ffe7df606b78489639bc0b827913bd09e1246fa6802968a5b3694c53e0dd9";

type KernelStorageConstructorParams =
  | [signer?: Signer]
  | ConstructorParameters<typeof ContractFactory>;

const isSuperArgs = (
  xs: KernelStorageConstructorParams
): xs is ConstructorParameters<typeof ContractFactory> => xs.length > 1;

export class KernelStorage__factory extends ContractFactory {
  constructor(...args: KernelStorageConstructorParams) {
    if (isSuperArgs(args)) {
      super(...args);
    } else {
      super(_abi, _bytecode, args[0]);
    }
  }

  override deploy(
    _entryPoint: PromiseOrValue<string>,
    overrides?: Overrides & { from?: PromiseOrValue<string> }
  ): Promise<KernelStorage> {
    return super.deploy(_entryPoint, overrides || {}) as Promise<KernelStorage>;
  }
  override getDeployTransaction(
    _entryPoint: PromiseOrValue<string>,
    overrides?: Overrides & { from?: PromiseOrValue<string> }
  ): TransactionRequest {
    return super.getDeployTransaction(_entryPoint, overrides || {});
  }
  override attach(address: string): KernelStorage {
    return super.attach(address) as KernelStorage;
  }
  override connect(signer: Signer): KernelStorage__factory {
    return super.connect(signer) as KernelStorage__factory;
  }

  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): KernelStorageInterface {
    return new utils.Interface(_abi) as KernelStorageInterface;
  }
  static connect(
    address: string,
    signerOrProvider: Signer | Provider
  ): KernelStorage {
    return new Contract(address, _abi, signerOrProvider) as KernelStorage;
  }
}
