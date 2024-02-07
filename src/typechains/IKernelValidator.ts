/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */
import type {
  BaseContract,
  BigNumber,
  BigNumberish,
  BytesLike,
  CallOverrides,
  ContractTransaction,
  PayableOverrides,
  PopulatedTransaction,
  Signer,
  utils,
} from "ethers";
import type { FunctionFragment, Result } from "@ethersproject/abi";
import type { Listener, Provider } from "@ethersproject/providers";
import type {
  TypedEventFilter,
  TypedEvent,
  TypedListener,
  OnEvent,
  PromiseOrValue,
} from "./common";

export type UserOperationStruct = {
  sender: PromiseOrValue<string>;
  nonce: PromiseOrValue<BigNumberish>;
  initCode: PromiseOrValue<BytesLike>;
  callData: PromiseOrValue<BytesLike>;
  callGasLimit: PromiseOrValue<BigNumberish>;
  verificationGasLimit: PromiseOrValue<BigNumberish>;
  preVerificationGas: PromiseOrValue<BigNumberish>;
  maxFeePerGas: PromiseOrValue<BigNumberish>;
  maxPriorityFeePerGas: PromiseOrValue<BigNumberish>;
  paymasterAndData: PromiseOrValue<BytesLike>;
  signature: PromiseOrValue<BytesLike>;
};

export type UserOperationStructOutput = [
  string,
  BigNumber,
  string,
  string,
  BigNumber,
  BigNumber,
  BigNumber,
  BigNumber,
  BigNumber,
  string,
  string
] & {
  sender: string;
  nonce: BigNumber;
  initCode: string;
  callData: string;
  callGasLimit: BigNumber;
  verificationGasLimit: BigNumber;
  preVerificationGas: BigNumber;
  maxFeePerGas: BigNumber;
  maxPriorityFeePerGas: BigNumber;
  paymasterAndData: string;
  signature: string;
};

export interface IKernelValidatorInterface extends utils.Interface {
  functions: {
    "disable(bytes)": FunctionFragment;
    "enable(bytes)": FunctionFragment;
    "validCaller(address,bytes)": FunctionFragment;
    "validateSignature(bytes32,bytes)": FunctionFragment;
    "validateUserOp((address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes),bytes32,uint256)": FunctionFragment;
  };

  getFunction(
    nameOrSignatureOrTopic:
      | "disable"
      | "enable"
      | "validCaller"
      | "validateSignature"
      | "validateUserOp"
  ): FunctionFragment;

  encodeFunctionData(
    functionFragment: "disable",
    values: [PromiseOrValue<BytesLike>]
  ): string;
  encodeFunctionData(
    functionFragment: "enable",
    values: [PromiseOrValue<BytesLike>]
  ): string;
  encodeFunctionData(
    functionFragment: "validCaller",
    values: [PromiseOrValue<string>, PromiseOrValue<BytesLike>]
  ): string;
  encodeFunctionData(
    functionFragment: "validateSignature",
    values: [PromiseOrValue<BytesLike>, PromiseOrValue<BytesLike>]
  ): string;
  encodeFunctionData(
    functionFragment: "validateUserOp",
    values: [
      UserOperationStruct,
      PromiseOrValue<BytesLike>,
      PromiseOrValue<BigNumberish>
    ]
  ): string;

  decodeFunctionResult(functionFragment: "disable", data: BytesLike): Result;
  decodeFunctionResult(functionFragment: "enable", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "validCaller",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "validateSignature",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "validateUserOp",
    data: BytesLike
  ): Result;

  events: {};
}

export interface IKernelValidator extends BaseContract {
  connect(signerOrProvider: Signer | Provider | string): this;
  attach(addressOrName: string): this;
  deployed(): Promise<this>;

  interface: IKernelValidatorInterface;

  queryFilter<TEvent extends TypedEvent>(
    event: TypedEventFilter<TEvent>,
    fromBlockOrBlockhash?: string | number | undefined,
    toBlock?: string | number | undefined
  ): Promise<Array<TEvent>>;

  listeners<TEvent extends TypedEvent>(
    eventFilter?: TypedEventFilter<TEvent>
  ): Array<TypedListener<TEvent>>;
  listeners(eventName?: string): Array<Listener>;
  removeAllListeners<TEvent extends TypedEvent>(
    eventFilter: TypedEventFilter<TEvent>
  ): this;
  removeAllListeners(eventName?: string): this;
  off: OnEvent<this>;
  on: OnEvent<this>;
  once: OnEvent<this>;
  removeListener: OnEvent<this>;

  functions: {
    disable(
      _data: PromiseOrValue<BytesLike>,
      overrides?: PayableOverrides & { from?: PromiseOrValue<string> }
    ): Promise<ContractTransaction>;

    enable(
      _data: PromiseOrValue<BytesLike>,
      overrides?: PayableOverrides & { from?: PromiseOrValue<string> }
    ): Promise<ContractTransaction>;

    validCaller(
      caller: PromiseOrValue<string>,
      data: PromiseOrValue<BytesLike>,
      overrides?: CallOverrides
    ): Promise<[boolean]>;

    validateSignature(
      hash: PromiseOrValue<BytesLike>,
      signature: PromiseOrValue<BytesLike>,
      overrides?: CallOverrides
    ): Promise<[BigNumber]>;

    validateUserOp(
      userOp: UserOperationStruct,
      userOpHash: PromiseOrValue<BytesLike>,
      missingFunds: PromiseOrValue<BigNumberish>,
      overrides?: PayableOverrides & { from?: PromiseOrValue<string> }
    ): Promise<ContractTransaction>;
  };

  disable(
    _data: PromiseOrValue<BytesLike>,
    overrides?: PayableOverrides & { from?: PromiseOrValue<string> }
  ): Promise<ContractTransaction>;

  enable(
    _data: PromiseOrValue<BytesLike>,
    overrides?: PayableOverrides & { from?: PromiseOrValue<string> }
  ): Promise<ContractTransaction>;

  validCaller(
    caller: PromiseOrValue<string>,
    data: PromiseOrValue<BytesLike>,
    overrides?: CallOverrides
  ): Promise<boolean>;

  validateSignature(
    hash: PromiseOrValue<BytesLike>,
    signature: PromiseOrValue<BytesLike>,
    overrides?: CallOverrides
  ): Promise<BigNumber>;

  validateUserOp(
    userOp: UserOperationStruct,
    userOpHash: PromiseOrValue<BytesLike>,
    missingFunds: PromiseOrValue<BigNumberish>,
    overrides?: PayableOverrides & { from?: PromiseOrValue<string> }
  ): Promise<ContractTransaction>;

  callStatic: {
    disable(
      _data: PromiseOrValue<BytesLike>,
      overrides?: CallOverrides
    ): Promise<void>;

    enable(
      _data: PromiseOrValue<BytesLike>,
      overrides?: CallOverrides
    ): Promise<void>;

    validCaller(
      caller: PromiseOrValue<string>,
      data: PromiseOrValue<BytesLike>,
      overrides?: CallOverrides
    ): Promise<boolean>;

    validateSignature(
      hash: PromiseOrValue<BytesLike>,
      signature: PromiseOrValue<BytesLike>,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    validateUserOp(
      userOp: UserOperationStruct,
      userOpHash: PromiseOrValue<BytesLike>,
      missingFunds: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<BigNumber>;
  };

  filters: {};

  estimateGas: {
    disable(
      _data: PromiseOrValue<BytesLike>,
      overrides?: PayableOverrides & { from?: PromiseOrValue<string> }
    ): Promise<BigNumber>;

    enable(
      _data: PromiseOrValue<BytesLike>,
      overrides?: PayableOverrides & { from?: PromiseOrValue<string> }
    ): Promise<BigNumber>;

    validCaller(
      caller: PromiseOrValue<string>,
      data: PromiseOrValue<BytesLike>,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    validateSignature(
      hash: PromiseOrValue<BytesLike>,
      signature: PromiseOrValue<BytesLike>,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    validateUserOp(
      userOp: UserOperationStruct,
      userOpHash: PromiseOrValue<BytesLike>,
      missingFunds: PromiseOrValue<BigNumberish>,
      overrides?: PayableOverrides & { from?: PromiseOrValue<string> }
    ): Promise<BigNumber>;
  };

  populateTransaction: {
    disable(
      _data: PromiseOrValue<BytesLike>,
      overrides?: PayableOverrides & { from?: PromiseOrValue<string> }
    ): Promise<PopulatedTransaction>;

    enable(
      _data: PromiseOrValue<BytesLike>,
      overrides?: PayableOverrides & { from?: PromiseOrValue<string> }
    ): Promise<PopulatedTransaction>;

    validCaller(
      caller: PromiseOrValue<string>,
      data: PromiseOrValue<BytesLike>,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    validateSignature(
      hash: PromiseOrValue<BytesLike>,
      signature: PromiseOrValue<BytesLike>,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    validateUserOp(
      userOp: UserOperationStruct,
      userOpHash: PromiseOrValue<BytesLike>,
      missingFunds: PromiseOrValue<BigNumberish>,
      overrides?: PayableOverrides & { from?: PromiseOrValue<string> }
    ): Promise<PopulatedTransaction>;
  };
}
