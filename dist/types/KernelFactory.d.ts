import type { BaseContract, BigNumber, BigNumberish, BytesLike, CallOverrides, ContractTransaction, Overrides, PopulatedTransaction, Signer, utils } from "ethers";
import type { FunctionFragment, Result, EventFragment } from "@ethersproject/abi";
import type { Listener, Provider } from "@ethersproject/providers";
import type { TypedEventFilter, TypedEvent, TypedListener, OnEvent, PromiseOrValue } from "./common";
export interface KernelFactoryInterface extends utils.Interface {
    functions: {
        "createAccount(address,uint256)": FunctionFragment;
        "getAccountAddress(address,uint256)": FunctionFragment;
        "kernelTemplate()": FunctionFragment;
    };
    getFunction(nameOrSignatureOrTopic: "createAccount" | "getAccountAddress" | "kernelTemplate"): FunctionFragment;
    encodeFunctionData(functionFragment: "createAccount", values: [PromiseOrValue<string>, PromiseOrValue<BigNumberish>]): string;
    encodeFunctionData(functionFragment: "getAccountAddress", values: [PromiseOrValue<string>, PromiseOrValue<BigNumberish>]): string;
    encodeFunctionData(functionFragment: "kernelTemplate", values?: undefined): string;
    decodeFunctionResult(functionFragment: "createAccount", data: BytesLike): Result;
    decodeFunctionResult(functionFragment: "getAccountAddress", data: BytesLike): Result;
    decodeFunctionResult(functionFragment: "kernelTemplate", data: BytesLike): Result;
    events: {
        "AccountCreated(address,address,uint256)": EventFragment;
    };
    getEvent(nameOrSignatureOrTopic: "AccountCreated"): EventFragment;
}
export interface AccountCreatedEventObject {
    account: string;
    owner: string;
    index: BigNumber;
}
export type AccountCreatedEvent = TypedEvent<[
    string,
    string,
    BigNumber
], AccountCreatedEventObject>;
export type AccountCreatedEventFilter = TypedEventFilter<AccountCreatedEvent>;
export interface KernelFactory extends BaseContract {
    connect(signerOrProvider: Signer | Provider | string): this;
    attach(addressOrName: string): this;
    deployed(): Promise<this>;
    interface: KernelFactoryInterface;
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
        createAccount(_owner: PromiseOrValue<string>, _index: PromiseOrValue<BigNumberish>, overrides?: Overrides & {
            from?: PromiseOrValue<string>;
        }): Promise<ContractTransaction>;
        getAccountAddress(_owner: PromiseOrValue<string>, _index: PromiseOrValue<BigNumberish>, overrides?: CallOverrides): Promise<[string]>;
        kernelTemplate(overrides?: CallOverrides): Promise<[string]>;
    };
    createAccount(_owner: PromiseOrValue<string>, _index: PromiseOrValue<BigNumberish>, overrides?: Overrides & {
        from?: PromiseOrValue<string>;
    }): Promise<ContractTransaction>;
    getAccountAddress(_owner: PromiseOrValue<string>, _index: PromiseOrValue<BigNumberish>, overrides?: CallOverrides): Promise<string>;
    kernelTemplate(overrides?: CallOverrides): Promise<string>;
    callStatic: {
        createAccount(_owner: PromiseOrValue<string>, _index: PromiseOrValue<BigNumberish>, overrides?: CallOverrides): Promise<string>;
        getAccountAddress(_owner: PromiseOrValue<string>, _index: PromiseOrValue<BigNumberish>, overrides?: CallOverrides): Promise<string>;
        kernelTemplate(overrides?: CallOverrides): Promise<string>;
    };
    filters: {
        "AccountCreated(address,address,uint256)"(account?: PromiseOrValue<string> | null, owner?: PromiseOrValue<string> | null, index?: null): AccountCreatedEventFilter;
        AccountCreated(account?: PromiseOrValue<string> | null, owner?: PromiseOrValue<string> | null, index?: null): AccountCreatedEventFilter;
    };
    estimateGas: {
        createAccount(_owner: PromiseOrValue<string>, _index: PromiseOrValue<BigNumberish>, overrides?: Overrides & {
            from?: PromiseOrValue<string>;
        }): Promise<BigNumber>;
        getAccountAddress(_owner: PromiseOrValue<string>, _index: PromiseOrValue<BigNumberish>, overrides?: CallOverrides): Promise<BigNumber>;
        kernelTemplate(overrides?: CallOverrides): Promise<BigNumber>;
    };
    populateTransaction: {
        createAccount(_owner: PromiseOrValue<string>, _index: PromiseOrValue<BigNumberish>, overrides?: Overrides & {
            from?: PromiseOrValue<string>;
        }): Promise<PopulatedTransaction>;
        getAccountAddress(_owner: PromiseOrValue<string>, _index: PromiseOrValue<BigNumberish>, overrides?: CallOverrides): Promise<PopulatedTransaction>;
        kernelTemplate(overrides?: CallOverrides): Promise<PopulatedTransaction>;
    };
}
