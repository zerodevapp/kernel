import type { BaseContract, BigNumber, BytesLike, CallOverrides, ContractTransaction, Overrides, PopulatedTransaction, Signer, utils } from "ethers";
import type { FunctionFragment, Result, EventFragment } from "@ethersproject/abi";
import type { Listener, Provider } from "@ethersproject/providers";
import type { TypedEventFilter, TypedEvent, TypedListener, OnEvent, PromiseOrValue } from "./common";
export interface KernelStorageInterface extends utils.Interface {
    functions: {
        "entryPoint()": FunctionFragment;
        "getNonce()": FunctionFragment;
        "getOwner()": FunctionFragment;
        "upgradeTo(address)": FunctionFragment;
    };
    getFunction(nameOrSignatureOrTopic: "entryPoint" | "getNonce" | "getOwner" | "upgradeTo"): FunctionFragment;
    encodeFunctionData(functionFragment: "entryPoint", values?: undefined): string;
    encodeFunctionData(functionFragment: "getNonce", values?: undefined): string;
    encodeFunctionData(functionFragment: "getOwner", values?: undefined): string;
    encodeFunctionData(functionFragment: "upgradeTo", values: [PromiseOrValue<string>]): string;
    decodeFunctionResult(functionFragment: "entryPoint", data: BytesLike): Result;
    decodeFunctionResult(functionFragment: "getNonce", data: BytesLike): Result;
    decodeFunctionResult(functionFragment: "getOwner", data: BytesLike): Result;
    decodeFunctionResult(functionFragment: "upgradeTo", data: BytesLike): Result;
    events: {
        "Upgraded(address)": EventFragment;
    };
    getEvent(nameOrSignatureOrTopic: "Upgraded"): EventFragment;
}
export interface UpgradedEventObject {
    newImplementation: string;
}
export type UpgradedEvent = TypedEvent<[string], UpgradedEventObject>;
export type UpgradedEventFilter = TypedEventFilter<UpgradedEvent>;
export interface KernelStorage extends BaseContract {
    connect(signerOrProvider: Signer | Provider | string): this;
    attach(addressOrName: string): this;
    deployed(): Promise<this>;
    interface: KernelStorageInterface;
    queryFilter<TEvent extends TypedEvent>(event: TypedEventFilter<TEvent>, fromBlockOrBlockhash?: string | number | undefined, toBlock?: string | number | undefined): Promise<Array<TEvent>>;
    listeners<TEvent extends TypedEvent>(eventFilter?: TypedEventFilter<TEvent>): Array<TypedListener<TEvent>>;
    listeners(eventName?: string): Array<Listener>;
    removeAllListeners<TEvent extends TypedEvent>(eventFilter: TypedEventFilter<TEvent>): this;
    removeAllListeners(eventName?: string): this;
    off: OnEvent<this>;
    on: OnEvent<this>;
    once: OnEvent<this>;
    removeListener: OnEvent<this>;
    functions: {
        entryPoint(overrides?: CallOverrides): Promise<[string]>;
        getNonce(overrides?: CallOverrides): Promise<[BigNumber]>;
        getOwner(overrides?: CallOverrides): Promise<[string]>;
        upgradeTo(_newImplementation: PromiseOrValue<string>, overrides?: Overrides & {
            from?: PromiseOrValue<string>;
        }): Promise<ContractTransaction>;
    };
    entryPoint(overrides?: CallOverrides): Promise<string>;
    getNonce(overrides?: CallOverrides): Promise<BigNumber>;
    getOwner(overrides?: CallOverrides): Promise<string>;
    upgradeTo(_newImplementation: PromiseOrValue<string>, overrides?: Overrides & {
        from?: PromiseOrValue<string>;
    }): Promise<ContractTransaction>;
    callStatic: {
        entryPoint(overrides?: CallOverrides): Promise<string>;
        getNonce(overrides?: CallOverrides): Promise<BigNumber>;
        getOwner(overrides?: CallOverrides): Promise<string>;
        upgradeTo(_newImplementation: PromiseOrValue<string>, overrides?: CallOverrides): Promise<void>;
    };
    filters: {
        "Upgraded(address)"(newImplementation?: PromiseOrValue<string> | null): UpgradedEventFilter;
        Upgraded(newImplementation?: PromiseOrValue<string> | null): UpgradedEventFilter;
    };
    estimateGas: {
        entryPoint(overrides?: CallOverrides): Promise<BigNumber>;
        getNonce(overrides?: CallOverrides): Promise<BigNumber>;
        getOwner(overrides?: CallOverrides): Promise<BigNumber>;
        upgradeTo(_newImplementation: PromiseOrValue<string>, overrides?: Overrides & {
            from?: PromiseOrValue<string>;
        }): Promise<BigNumber>;
    };
    populateTransaction: {
        entryPoint(overrides?: CallOverrides): Promise<PopulatedTransaction>;
        getNonce(overrides?: CallOverrides): Promise<PopulatedTransaction>;
        getOwner(overrides?: CallOverrides): Promise<PopulatedTransaction>;
        upgradeTo(_newImplementation: PromiseOrValue<string>, overrides?: Overrides & {
            from?: PromiseOrValue<string>;
        }): Promise<PopulatedTransaction>;
    };
}
