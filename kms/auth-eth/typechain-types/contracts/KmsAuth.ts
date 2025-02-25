/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */
import type {
  BaseContract,
  BigNumberish,
  BytesLike,
  FunctionFragment,
  Result,
  Interface,
  EventFragment,
  AddressLike,
  ContractRunner,
  ContractMethod,
  Listener,
} from "ethers";
import type {
  TypedContractEvent,
  TypedDeferredTopicFilter,
  TypedEventLog,
  TypedLogDescription,
  TypedListener,
  TypedContractMethod,
} from "../common";

export declare namespace IAppAuth {
  export type AppBootInfoStruct = {
    appId: AddressLike;
    composeHash: BytesLike;
    instanceId: AddressLike;
    deviceId: BytesLike;
    mrAggregated: BytesLike;
    mrImage: BytesLike;
  };

  export type AppBootInfoStructOutput = [
    appId: string,
    composeHash: string,
    instanceId: string,
    deviceId: string,
    mrAggregated: string,
    mrImage: string
  ] & {
    appId: string;
    composeHash: string;
    instanceId: string;
    deviceId: string;
    mrAggregated: string;
    mrImage: string;
  };
}

export declare namespace KmsAuth {
  export type KmsInfoStruct = {
    k256Pubkey: BytesLike;
    caPubkey: BytesLike;
    quote: BytesLike;
    eventlog: BytesLike;
  };

  export type KmsInfoStructOutput = [
    k256Pubkey: string,
    caPubkey: string,
    quote: string,
    eventlog: string
  ] & { k256Pubkey: string; caPubkey: string; quote: string; eventlog: string };
}

export interface KmsAuthInterface extends Interface {
  getFunction(
    nameOrSignature:
      | "UPGRADE_INTERFACE_VERSION"
      | "allowedAggregatedMrs"
      | "allowedImages"
      | "allowedKmsComposeHashes"
      | "allowedKmsDeviceIds"
      | "apps"
      | "calculateAppId"
      | "deregisterAggregatedMr"
      | "deregisterImage"
      | "deregisterKmsComposeHash"
      | "deregisterKmsDeviceId"
      | "initialize"
      | "isAppAllowed"
      | "isKmsAllowed"
      | "kmsInfo"
      | "owner"
      | "proxiableUUID"
      | "registerAggregatedMr"
      | "registerApp"
      | "registerImage"
      | "registerKmsComposeHash"
      | "registerKmsDeviceId"
      | "renounceOwnership"
      | "setKmsEventlog"
      | "setKmsInfo"
      | "setKmsQuote"
      | "setTProxyAppId"
      | "tproxyAppId"
      | "transferOwnership"
      | "upgradeToAndCall"
  ): FunctionFragment;

  getEvent(
    nameOrSignatureOrTopic:
      | "AggregatedMrDeregistered"
      | "AggregatedMrRegistered"
      | "AppRegistered"
      | "ImageDeregistered"
      | "ImageRegistered"
      | "Initialized"
      | "KmsComposeHashDeregistered"
      | "KmsComposeHashRegistered"
      | "KmsDeviceIdDeregistered"
      | "KmsDeviceIdRegistered"
      | "KmsInfoSet"
      | "OwnershipTransferred"
      | "TProxyAppIdSet"
      | "Upgraded"
  ): EventFragment;

  encodeFunctionData(
    functionFragment: "UPGRADE_INTERFACE_VERSION",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "allowedAggregatedMrs",
    values: [BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "allowedImages",
    values: [BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "allowedKmsComposeHashes",
    values: [BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "allowedKmsDeviceIds",
    values: [BytesLike]
  ): string;
  encodeFunctionData(functionFragment: "apps", values: [AddressLike]): string;
  encodeFunctionData(
    functionFragment: "calculateAppId",
    values: [AddressLike, BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "deregisterAggregatedMr",
    values: [BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "deregisterImage",
    values: [BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "deregisterKmsComposeHash",
    values: [BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "deregisterKmsDeviceId",
    values: [BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "initialize",
    values: [AddressLike]
  ): string;
  encodeFunctionData(
    functionFragment: "isAppAllowed",
    values: [IAppAuth.AppBootInfoStruct]
  ): string;
  encodeFunctionData(
    functionFragment: "isKmsAllowed",
    values: [IAppAuth.AppBootInfoStruct]
  ): string;
  encodeFunctionData(functionFragment: "kmsInfo", values?: undefined): string;
  encodeFunctionData(functionFragment: "owner", values?: undefined): string;
  encodeFunctionData(
    functionFragment: "proxiableUUID",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "registerAggregatedMr",
    values: [BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "registerApp",
    values: [BytesLike, AddressLike]
  ): string;
  encodeFunctionData(
    functionFragment: "registerImage",
    values: [BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "registerKmsComposeHash",
    values: [BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "registerKmsDeviceId",
    values: [BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "renounceOwnership",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "setKmsEventlog",
    values: [BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "setKmsInfo",
    values: [KmsAuth.KmsInfoStruct]
  ): string;
  encodeFunctionData(
    functionFragment: "setKmsQuote",
    values: [BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "setTProxyAppId",
    values: [string]
  ): string;
  encodeFunctionData(
    functionFragment: "tproxyAppId",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "transferOwnership",
    values: [AddressLike]
  ): string;
  encodeFunctionData(
    functionFragment: "upgradeToAndCall",
    values: [AddressLike, BytesLike]
  ): string;

  decodeFunctionResult(
    functionFragment: "UPGRADE_INTERFACE_VERSION",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "allowedAggregatedMrs",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "allowedImages",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "allowedKmsComposeHashes",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "allowedKmsDeviceIds",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "apps", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "calculateAppId",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "deregisterAggregatedMr",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "deregisterImage",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "deregisterKmsComposeHash",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "deregisterKmsDeviceId",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "initialize", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "isAppAllowed",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "isKmsAllowed",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "kmsInfo", data: BytesLike): Result;
  decodeFunctionResult(functionFragment: "owner", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "proxiableUUID",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "registerAggregatedMr",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "registerApp",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "registerImage",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "registerKmsComposeHash",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "registerKmsDeviceId",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "renounceOwnership",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "setKmsEventlog",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "setKmsInfo", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "setKmsQuote",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "setTProxyAppId",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "tproxyAppId",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "transferOwnership",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "upgradeToAndCall",
    data: BytesLike
  ): Result;
}

export namespace AggregatedMrDeregisteredEvent {
  export type InputTuple = [mrAggregated: BytesLike];
  export type OutputTuple = [mrAggregated: string];
  export interface OutputObject {
    mrAggregated: string;
  }
  export type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
  export type Filter = TypedDeferredTopicFilter<Event>;
  export type Log = TypedEventLog<Event>;
  export type LogDescription = TypedLogDescription<Event>;
}

export namespace AggregatedMrRegisteredEvent {
  export type InputTuple = [mrAggregated: BytesLike];
  export type OutputTuple = [mrAggregated: string];
  export interface OutputObject {
    mrAggregated: string;
  }
  export type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
  export type Filter = TypedDeferredTopicFilter<Event>;
  export type Log = TypedEventLog<Event>;
  export type LogDescription = TypedLogDescription<Event>;
}

export namespace AppRegisteredEvent {
  export type InputTuple = [appId: AddressLike];
  export type OutputTuple = [appId: string];
  export interface OutputObject {
    appId: string;
  }
  export type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
  export type Filter = TypedDeferredTopicFilter<Event>;
  export type Log = TypedEventLog<Event>;
  export type LogDescription = TypedLogDescription<Event>;
}

export namespace ImageDeregisteredEvent {
  export type InputTuple = [mrImage: BytesLike];
  export type OutputTuple = [mrImage: string];
  export interface OutputObject {
    mrImage: string;
  }
  export type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
  export type Filter = TypedDeferredTopicFilter<Event>;
  export type Log = TypedEventLog<Event>;
  export type LogDescription = TypedLogDescription<Event>;
}

export namespace ImageRegisteredEvent {
  export type InputTuple = [mrImage: BytesLike];
  export type OutputTuple = [mrImage: string];
  export interface OutputObject {
    mrImage: string;
  }
  export type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
  export type Filter = TypedDeferredTopicFilter<Event>;
  export type Log = TypedEventLog<Event>;
  export type LogDescription = TypedLogDescription<Event>;
}

export namespace InitializedEvent {
  export type InputTuple = [version: BigNumberish];
  export type OutputTuple = [version: bigint];
  export interface OutputObject {
    version: bigint;
  }
  export type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
  export type Filter = TypedDeferredTopicFilter<Event>;
  export type Log = TypedEventLog<Event>;
  export type LogDescription = TypedLogDescription<Event>;
}

export namespace KmsComposeHashDeregisteredEvent {
  export type InputTuple = [composeHash: BytesLike];
  export type OutputTuple = [composeHash: string];
  export interface OutputObject {
    composeHash: string;
  }
  export type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
  export type Filter = TypedDeferredTopicFilter<Event>;
  export type Log = TypedEventLog<Event>;
  export type LogDescription = TypedLogDescription<Event>;
}

export namespace KmsComposeHashRegisteredEvent {
  export type InputTuple = [composeHash: BytesLike];
  export type OutputTuple = [composeHash: string];
  export interface OutputObject {
    composeHash: string;
  }
  export type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
  export type Filter = TypedDeferredTopicFilter<Event>;
  export type Log = TypedEventLog<Event>;
  export type LogDescription = TypedLogDescription<Event>;
}

export namespace KmsDeviceIdDeregisteredEvent {
  export type InputTuple = [deviceId: BytesLike];
  export type OutputTuple = [deviceId: string];
  export interface OutputObject {
    deviceId: string;
  }
  export type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
  export type Filter = TypedDeferredTopicFilter<Event>;
  export type Log = TypedEventLog<Event>;
  export type LogDescription = TypedLogDescription<Event>;
}

export namespace KmsDeviceIdRegisteredEvent {
  export type InputTuple = [deviceId: BytesLike];
  export type OutputTuple = [deviceId: string];
  export interface OutputObject {
    deviceId: string;
  }
  export type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
  export type Filter = TypedDeferredTopicFilter<Event>;
  export type Log = TypedEventLog<Event>;
  export type LogDescription = TypedLogDescription<Event>;
}

export namespace KmsInfoSetEvent {
  export type InputTuple = [k256Pubkey: BytesLike];
  export type OutputTuple = [k256Pubkey: string];
  export interface OutputObject {
    k256Pubkey: string;
  }
  export type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
  export type Filter = TypedDeferredTopicFilter<Event>;
  export type Log = TypedEventLog<Event>;
  export type LogDescription = TypedLogDescription<Event>;
}

export namespace OwnershipTransferredEvent {
  export type InputTuple = [previousOwner: AddressLike, newOwner: AddressLike];
  export type OutputTuple = [previousOwner: string, newOwner: string];
  export interface OutputObject {
    previousOwner: string;
    newOwner: string;
  }
  export type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
  export type Filter = TypedDeferredTopicFilter<Event>;
  export type Log = TypedEventLog<Event>;
  export type LogDescription = TypedLogDescription<Event>;
}

export namespace TProxyAppIdSetEvent {
  export type InputTuple = [tproxyAppId: string];
  export type OutputTuple = [tproxyAppId: string];
  export interface OutputObject {
    tproxyAppId: string;
  }
  export type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
  export type Filter = TypedDeferredTopicFilter<Event>;
  export type Log = TypedEventLog<Event>;
  export type LogDescription = TypedLogDescription<Event>;
}

export namespace UpgradedEvent {
  export type InputTuple = [implementation: AddressLike];
  export type OutputTuple = [implementation: string];
  export interface OutputObject {
    implementation: string;
  }
  export type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
  export type Filter = TypedDeferredTopicFilter<Event>;
  export type Log = TypedEventLog<Event>;
  export type LogDescription = TypedLogDescription<Event>;
}

export interface KmsAuth extends BaseContract {
  connect(runner?: ContractRunner | null): KmsAuth;
  waitForDeployment(): Promise<this>;

  interface: KmsAuthInterface;

  queryFilter<TCEvent extends TypedContractEvent>(
    event: TCEvent,
    fromBlockOrBlockhash?: string | number | undefined,
    toBlock?: string | number | undefined
  ): Promise<Array<TypedEventLog<TCEvent>>>;
  queryFilter<TCEvent extends TypedContractEvent>(
    filter: TypedDeferredTopicFilter<TCEvent>,
    fromBlockOrBlockhash?: string | number | undefined,
    toBlock?: string | number | undefined
  ): Promise<Array<TypedEventLog<TCEvent>>>;

  on<TCEvent extends TypedContractEvent>(
    event: TCEvent,
    listener: TypedListener<TCEvent>
  ): Promise<this>;
  on<TCEvent extends TypedContractEvent>(
    filter: TypedDeferredTopicFilter<TCEvent>,
    listener: TypedListener<TCEvent>
  ): Promise<this>;

  once<TCEvent extends TypedContractEvent>(
    event: TCEvent,
    listener: TypedListener<TCEvent>
  ): Promise<this>;
  once<TCEvent extends TypedContractEvent>(
    filter: TypedDeferredTopicFilter<TCEvent>,
    listener: TypedListener<TCEvent>
  ): Promise<this>;

  listeners<TCEvent extends TypedContractEvent>(
    event: TCEvent
  ): Promise<Array<TypedListener<TCEvent>>>;
  listeners(eventName?: string): Promise<Array<Listener>>;
  removeAllListeners<TCEvent extends TypedContractEvent>(
    event?: TCEvent
  ): Promise<this>;

  UPGRADE_INTERFACE_VERSION: TypedContractMethod<[], [string], "view">;

  allowedAggregatedMrs: TypedContractMethod<
    [arg0: BytesLike],
    [boolean],
    "view"
  >;

  allowedImages: TypedContractMethod<[arg0: BytesLike], [boolean], "view">;

  allowedKmsComposeHashes: TypedContractMethod<
    [arg0: BytesLike],
    [boolean],
    "view"
  >;

  allowedKmsDeviceIds: TypedContractMethod<
    [arg0: BytesLike],
    [boolean],
    "view"
  >;

  apps: TypedContractMethod<
    [arg0: AddressLike],
    [[boolean, string] & { isRegistered: boolean; controller: string }],
    "view"
  >;

  calculateAppId: TypedContractMethod<
    [sender: AddressLike, salt: BytesLike],
    [string],
    "view"
  >;

  deregisterAggregatedMr: TypedContractMethod<
    [mrAggregated: BytesLike],
    [void],
    "nonpayable"
  >;

  deregisterImage: TypedContractMethod<
    [mrImage: BytesLike],
    [void],
    "nonpayable"
  >;

  deregisterKmsComposeHash: TypedContractMethod<
    [composeHash: BytesLike],
    [void],
    "nonpayable"
  >;

  deregisterKmsDeviceId: TypedContractMethod<
    [deviceId: BytesLike],
    [void],
    "nonpayable"
  >;

  initialize: TypedContractMethod<
    [initialOwner: AddressLike],
    [void],
    "nonpayable"
  >;

  isAppAllowed: TypedContractMethod<
    [bootInfo: IAppAuth.AppBootInfoStruct],
    [[boolean, string] & { isAllowed: boolean; reason: string }],
    "view"
  >;

  isKmsAllowed: TypedContractMethod<
    [bootInfo: IAppAuth.AppBootInfoStruct],
    [[boolean, string] & { isAllowed: boolean; reason: string }],
    "view"
  >;

  kmsInfo: TypedContractMethod<
    [],
    [
      [string, string, string, string] & {
        k256Pubkey: string;
        caPubkey: string;
        quote: string;
        eventlog: string;
      }
    ],
    "view"
  >;

  owner: TypedContractMethod<[], [string], "view">;

  proxiableUUID: TypedContractMethod<[], [string], "view">;

  registerAggregatedMr: TypedContractMethod<
    [mrAggregated: BytesLike],
    [void],
    "nonpayable"
  >;

  registerApp: TypedContractMethod<
    [salt: BytesLike, controller: AddressLike],
    [void],
    "nonpayable"
  >;

  registerImage: TypedContractMethod<
    [mrImage: BytesLike],
    [void],
    "nonpayable"
  >;

  registerKmsComposeHash: TypedContractMethod<
    [composeHash: BytesLike],
    [void],
    "nonpayable"
  >;

  registerKmsDeviceId: TypedContractMethod<
    [deviceId: BytesLike],
    [void],
    "nonpayable"
  >;

  renounceOwnership: TypedContractMethod<[], [void], "nonpayable">;

  setKmsEventlog: TypedContractMethod<
    [eventlog: BytesLike],
    [void],
    "nonpayable"
  >;

  setKmsInfo: TypedContractMethod<
    [info: KmsAuth.KmsInfoStruct],
    [void],
    "nonpayable"
  >;

  setKmsQuote: TypedContractMethod<[quote: BytesLike], [void], "nonpayable">;

  setTProxyAppId: TypedContractMethod<[appId: string], [void], "nonpayable">;

  tproxyAppId: TypedContractMethod<[], [string], "view">;

  transferOwnership: TypedContractMethod<
    [newOwner: AddressLike],
    [void],
    "nonpayable"
  >;

  upgradeToAndCall: TypedContractMethod<
    [newImplementation: AddressLike, data: BytesLike],
    [void],
    "payable"
  >;

  getFunction<T extends ContractMethod = ContractMethod>(
    key: string | FunctionFragment
  ): T;

  getFunction(
    nameOrSignature: "UPGRADE_INTERFACE_VERSION"
  ): TypedContractMethod<[], [string], "view">;
  getFunction(
    nameOrSignature: "allowedAggregatedMrs"
  ): TypedContractMethod<[arg0: BytesLike], [boolean], "view">;
  getFunction(
    nameOrSignature: "allowedImages"
  ): TypedContractMethod<[arg0: BytesLike], [boolean], "view">;
  getFunction(
    nameOrSignature: "allowedKmsComposeHashes"
  ): TypedContractMethod<[arg0: BytesLike], [boolean], "view">;
  getFunction(
    nameOrSignature: "allowedKmsDeviceIds"
  ): TypedContractMethod<[arg0: BytesLike], [boolean], "view">;
  getFunction(
    nameOrSignature: "apps"
  ): TypedContractMethod<
    [arg0: AddressLike],
    [[boolean, string] & { isRegistered: boolean; controller: string }],
    "view"
  >;
  getFunction(
    nameOrSignature: "calculateAppId"
  ): TypedContractMethod<
    [sender: AddressLike, salt: BytesLike],
    [string],
    "view"
  >;
  getFunction(
    nameOrSignature: "deregisterAggregatedMr"
  ): TypedContractMethod<[mrAggregated: BytesLike], [void], "nonpayable">;
  getFunction(
    nameOrSignature: "deregisterImage"
  ): TypedContractMethod<[mrImage: BytesLike], [void], "nonpayable">;
  getFunction(
    nameOrSignature: "deregisterKmsComposeHash"
  ): TypedContractMethod<[composeHash: BytesLike], [void], "nonpayable">;
  getFunction(
    nameOrSignature: "deregisterKmsDeviceId"
  ): TypedContractMethod<[deviceId: BytesLike], [void], "nonpayable">;
  getFunction(
    nameOrSignature: "initialize"
  ): TypedContractMethod<[initialOwner: AddressLike], [void], "nonpayable">;
  getFunction(
    nameOrSignature: "isAppAllowed"
  ): TypedContractMethod<
    [bootInfo: IAppAuth.AppBootInfoStruct],
    [[boolean, string] & { isAllowed: boolean; reason: string }],
    "view"
  >;
  getFunction(
    nameOrSignature: "isKmsAllowed"
  ): TypedContractMethod<
    [bootInfo: IAppAuth.AppBootInfoStruct],
    [[boolean, string] & { isAllowed: boolean; reason: string }],
    "view"
  >;
  getFunction(
    nameOrSignature: "kmsInfo"
  ): TypedContractMethod<
    [],
    [
      [string, string, string, string] & {
        k256Pubkey: string;
        caPubkey: string;
        quote: string;
        eventlog: string;
      }
    ],
    "view"
  >;
  getFunction(
    nameOrSignature: "owner"
  ): TypedContractMethod<[], [string], "view">;
  getFunction(
    nameOrSignature: "proxiableUUID"
  ): TypedContractMethod<[], [string], "view">;
  getFunction(
    nameOrSignature: "registerAggregatedMr"
  ): TypedContractMethod<[mrAggregated: BytesLike], [void], "nonpayable">;
  getFunction(
    nameOrSignature: "registerApp"
  ): TypedContractMethod<
    [salt: BytesLike, controller: AddressLike],
    [void],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "registerImage"
  ): TypedContractMethod<[mrImage: BytesLike], [void], "nonpayable">;
  getFunction(
    nameOrSignature: "registerKmsComposeHash"
  ): TypedContractMethod<[composeHash: BytesLike], [void], "nonpayable">;
  getFunction(
    nameOrSignature: "registerKmsDeviceId"
  ): TypedContractMethod<[deviceId: BytesLike], [void], "nonpayable">;
  getFunction(
    nameOrSignature: "renounceOwnership"
  ): TypedContractMethod<[], [void], "nonpayable">;
  getFunction(
    nameOrSignature: "setKmsEventlog"
  ): TypedContractMethod<[eventlog: BytesLike], [void], "nonpayable">;
  getFunction(
    nameOrSignature: "setKmsInfo"
  ): TypedContractMethod<[info: KmsAuth.KmsInfoStruct], [void], "nonpayable">;
  getFunction(
    nameOrSignature: "setKmsQuote"
  ): TypedContractMethod<[quote: BytesLike], [void], "nonpayable">;
  getFunction(
    nameOrSignature: "setTProxyAppId"
  ): TypedContractMethod<[appId: string], [void], "nonpayable">;
  getFunction(
    nameOrSignature: "tproxyAppId"
  ): TypedContractMethod<[], [string], "view">;
  getFunction(
    nameOrSignature: "transferOwnership"
  ): TypedContractMethod<[newOwner: AddressLike], [void], "nonpayable">;
  getFunction(
    nameOrSignature: "upgradeToAndCall"
  ): TypedContractMethod<
    [newImplementation: AddressLike, data: BytesLike],
    [void],
    "payable"
  >;

  getEvent(
    key: "AggregatedMrDeregistered"
  ): TypedContractEvent<
    AggregatedMrDeregisteredEvent.InputTuple,
    AggregatedMrDeregisteredEvent.OutputTuple,
    AggregatedMrDeregisteredEvent.OutputObject
  >;
  getEvent(
    key: "AggregatedMrRegistered"
  ): TypedContractEvent<
    AggregatedMrRegisteredEvent.InputTuple,
    AggregatedMrRegisteredEvent.OutputTuple,
    AggregatedMrRegisteredEvent.OutputObject
  >;
  getEvent(
    key: "AppRegistered"
  ): TypedContractEvent<
    AppRegisteredEvent.InputTuple,
    AppRegisteredEvent.OutputTuple,
    AppRegisteredEvent.OutputObject
  >;
  getEvent(
    key: "ImageDeregistered"
  ): TypedContractEvent<
    ImageDeregisteredEvent.InputTuple,
    ImageDeregisteredEvent.OutputTuple,
    ImageDeregisteredEvent.OutputObject
  >;
  getEvent(
    key: "ImageRegistered"
  ): TypedContractEvent<
    ImageRegisteredEvent.InputTuple,
    ImageRegisteredEvent.OutputTuple,
    ImageRegisteredEvent.OutputObject
  >;
  getEvent(
    key: "Initialized"
  ): TypedContractEvent<
    InitializedEvent.InputTuple,
    InitializedEvent.OutputTuple,
    InitializedEvent.OutputObject
  >;
  getEvent(
    key: "KmsComposeHashDeregistered"
  ): TypedContractEvent<
    KmsComposeHashDeregisteredEvent.InputTuple,
    KmsComposeHashDeregisteredEvent.OutputTuple,
    KmsComposeHashDeregisteredEvent.OutputObject
  >;
  getEvent(
    key: "KmsComposeHashRegistered"
  ): TypedContractEvent<
    KmsComposeHashRegisteredEvent.InputTuple,
    KmsComposeHashRegisteredEvent.OutputTuple,
    KmsComposeHashRegisteredEvent.OutputObject
  >;
  getEvent(
    key: "KmsDeviceIdDeregistered"
  ): TypedContractEvent<
    KmsDeviceIdDeregisteredEvent.InputTuple,
    KmsDeviceIdDeregisteredEvent.OutputTuple,
    KmsDeviceIdDeregisteredEvent.OutputObject
  >;
  getEvent(
    key: "KmsDeviceIdRegistered"
  ): TypedContractEvent<
    KmsDeviceIdRegisteredEvent.InputTuple,
    KmsDeviceIdRegisteredEvent.OutputTuple,
    KmsDeviceIdRegisteredEvent.OutputObject
  >;
  getEvent(
    key: "KmsInfoSet"
  ): TypedContractEvent<
    KmsInfoSetEvent.InputTuple,
    KmsInfoSetEvent.OutputTuple,
    KmsInfoSetEvent.OutputObject
  >;
  getEvent(
    key: "OwnershipTransferred"
  ): TypedContractEvent<
    OwnershipTransferredEvent.InputTuple,
    OwnershipTransferredEvent.OutputTuple,
    OwnershipTransferredEvent.OutputObject
  >;
  getEvent(
    key: "TProxyAppIdSet"
  ): TypedContractEvent<
    TProxyAppIdSetEvent.InputTuple,
    TProxyAppIdSetEvent.OutputTuple,
    TProxyAppIdSetEvent.OutputObject
  >;
  getEvent(
    key: "Upgraded"
  ): TypedContractEvent<
    UpgradedEvent.InputTuple,
    UpgradedEvent.OutputTuple,
    UpgradedEvent.OutputObject
  >;

  filters: {
    "AggregatedMrDeregistered(bytes32)": TypedContractEvent<
      AggregatedMrDeregisteredEvent.InputTuple,
      AggregatedMrDeregisteredEvent.OutputTuple,
      AggregatedMrDeregisteredEvent.OutputObject
    >;
    AggregatedMrDeregistered: TypedContractEvent<
      AggregatedMrDeregisteredEvent.InputTuple,
      AggregatedMrDeregisteredEvent.OutputTuple,
      AggregatedMrDeregisteredEvent.OutputObject
    >;

    "AggregatedMrRegistered(bytes32)": TypedContractEvent<
      AggregatedMrRegisteredEvent.InputTuple,
      AggregatedMrRegisteredEvent.OutputTuple,
      AggregatedMrRegisteredEvent.OutputObject
    >;
    AggregatedMrRegistered: TypedContractEvent<
      AggregatedMrRegisteredEvent.InputTuple,
      AggregatedMrRegisteredEvent.OutputTuple,
      AggregatedMrRegisteredEvent.OutputObject
    >;

    "AppRegistered(address)": TypedContractEvent<
      AppRegisteredEvent.InputTuple,
      AppRegisteredEvent.OutputTuple,
      AppRegisteredEvent.OutputObject
    >;
    AppRegistered: TypedContractEvent<
      AppRegisteredEvent.InputTuple,
      AppRegisteredEvent.OutputTuple,
      AppRegisteredEvent.OutputObject
    >;

    "ImageDeregistered(bytes32)": TypedContractEvent<
      ImageDeregisteredEvent.InputTuple,
      ImageDeregisteredEvent.OutputTuple,
      ImageDeregisteredEvent.OutputObject
    >;
    ImageDeregistered: TypedContractEvent<
      ImageDeregisteredEvent.InputTuple,
      ImageDeregisteredEvent.OutputTuple,
      ImageDeregisteredEvent.OutputObject
    >;

    "ImageRegistered(bytes32)": TypedContractEvent<
      ImageRegisteredEvent.InputTuple,
      ImageRegisteredEvent.OutputTuple,
      ImageRegisteredEvent.OutputObject
    >;
    ImageRegistered: TypedContractEvent<
      ImageRegisteredEvent.InputTuple,
      ImageRegisteredEvent.OutputTuple,
      ImageRegisteredEvent.OutputObject
    >;

    "Initialized(uint64)": TypedContractEvent<
      InitializedEvent.InputTuple,
      InitializedEvent.OutputTuple,
      InitializedEvent.OutputObject
    >;
    Initialized: TypedContractEvent<
      InitializedEvent.InputTuple,
      InitializedEvent.OutputTuple,
      InitializedEvent.OutputObject
    >;

    "KmsComposeHashDeregistered(bytes32)": TypedContractEvent<
      KmsComposeHashDeregisteredEvent.InputTuple,
      KmsComposeHashDeregisteredEvent.OutputTuple,
      KmsComposeHashDeregisteredEvent.OutputObject
    >;
    KmsComposeHashDeregistered: TypedContractEvent<
      KmsComposeHashDeregisteredEvent.InputTuple,
      KmsComposeHashDeregisteredEvent.OutputTuple,
      KmsComposeHashDeregisteredEvent.OutputObject
    >;

    "KmsComposeHashRegistered(bytes32)": TypedContractEvent<
      KmsComposeHashRegisteredEvent.InputTuple,
      KmsComposeHashRegisteredEvent.OutputTuple,
      KmsComposeHashRegisteredEvent.OutputObject
    >;
    KmsComposeHashRegistered: TypedContractEvent<
      KmsComposeHashRegisteredEvent.InputTuple,
      KmsComposeHashRegisteredEvent.OutputTuple,
      KmsComposeHashRegisteredEvent.OutputObject
    >;

    "KmsDeviceIdDeregistered(bytes32)": TypedContractEvent<
      KmsDeviceIdDeregisteredEvent.InputTuple,
      KmsDeviceIdDeregisteredEvent.OutputTuple,
      KmsDeviceIdDeregisteredEvent.OutputObject
    >;
    KmsDeviceIdDeregistered: TypedContractEvent<
      KmsDeviceIdDeregisteredEvent.InputTuple,
      KmsDeviceIdDeregisteredEvent.OutputTuple,
      KmsDeviceIdDeregisteredEvent.OutputObject
    >;

    "KmsDeviceIdRegistered(bytes32)": TypedContractEvent<
      KmsDeviceIdRegisteredEvent.InputTuple,
      KmsDeviceIdRegisteredEvent.OutputTuple,
      KmsDeviceIdRegisteredEvent.OutputObject
    >;
    KmsDeviceIdRegistered: TypedContractEvent<
      KmsDeviceIdRegisteredEvent.InputTuple,
      KmsDeviceIdRegisteredEvent.OutputTuple,
      KmsDeviceIdRegisteredEvent.OutputObject
    >;

    "KmsInfoSet(bytes)": TypedContractEvent<
      KmsInfoSetEvent.InputTuple,
      KmsInfoSetEvent.OutputTuple,
      KmsInfoSetEvent.OutputObject
    >;
    KmsInfoSet: TypedContractEvent<
      KmsInfoSetEvent.InputTuple,
      KmsInfoSetEvent.OutputTuple,
      KmsInfoSetEvent.OutputObject
    >;

    "OwnershipTransferred(address,address)": TypedContractEvent<
      OwnershipTransferredEvent.InputTuple,
      OwnershipTransferredEvent.OutputTuple,
      OwnershipTransferredEvent.OutputObject
    >;
    OwnershipTransferred: TypedContractEvent<
      OwnershipTransferredEvent.InputTuple,
      OwnershipTransferredEvent.OutputTuple,
      OwnershipTransferredEvent.OutputObject
    >;

    "TProxyAppIdSet(string)": TypedContractEvent<
      TProxyAppIdSetEvent.InputTuple,
      TProxyAppIdSetEvent.OutputTuple,
      TProxyAppIdSetEvent.OutputObject
    >;
    TProxyAppIdSet: TypedContractEvent<
      TProxyAppIdSetEvent.InputTuple,
      TProxyAppIdSetEvent.OutputTuple,
      TProxyAppIdSetEvent.OutputObject
    >;

    "Upgraded(address)": TypedContractEvent<
      UpgradedEvent.InputTuple,
      UpgradedEvent.OutputTuple,
      UpgradedEvent.OutputObject
    >;
    Upgraded: TypedContractEvent<
      UpgradedEvent.InputTuple,
      UpgradedEvent.OutputTuple,
      UpgradedEvent.OutputObject
    >;
  };
}
