/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */
import type {
  BaseContract,
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
} from "./common";

export declare namespace IAppAuth {
  export type AppBootInfoStruct = {
    appId: AddressLike;
    composeHash: BytesLike;
    instanceId: AddressLike;
    deviceId: BytesLike;
    mrEnclave: BytesLike;
    mrImage: BytesLike;
  };

  export type AppBootInfoStructOutput = [
    appId: string,
    composeHash: string,
    instanceId: string,
    deviceId: string,
    mrEnclave: string,
    mrImage: string
  ] & {
    appId: string;
    composeHash: string;
    instanceId: string;
    deviceId: string;
    mrEnclave: string;
    mrImage: string;
  };
}

export declare namespace KmsAuth {
  export type KmsInfoStruct = {
    k256Pubkey: BytesLike;
    caPubkey: BytesLike;
    quote: BytesLike;
  };

  export type KmsInfoStructOutput = [
    k256Pubkey: string,
    caPubkey: string,
    quote: string
  ] & { k256Pubkey: string; caPubkey: string; quote: string };
}

export interface KmsAuthInterface extends Interface {
  getFunction(
    nameOrSignature:
      | "allowedEnclaves"
      | "allowedImages"
      | "allowedKmsComposeHashes"
      | "allowedKmsDeviceIds"
      | "apps"
      | "calculateAppId"
      | "deregisterEnclave"
      | "deregisterImage"
      | "deregisterKmsComposeHash"
      | "deregisterKmsDeviceId"
      | "isAppAllowed"
      | "isKmsAllowed"
      | "kmsInfo"
      | "owner"
      | "registerApp"
      | "registerEnclave"
      | "registerImage"
      | "registerKmsComposeHash"
      | "registerKmsDeviceId"
      | "setKmsInfo"
      | "setTProxyAppId"
      | "tproxyAppId"
      | "transferOwnership"
  ): FunctionFragment;

  getEvent(
    nameOrSignatureOrTopic:
      | "AppRegistered"
      | "EnclaveDeregistered"
      | "EnclaveRegistered"
      | "ImageDeregistered"
      | "ImageRegistered"
      | "KmsComposeHashDeregistered"
      | "KmsComposeHashRegistered"
      | "KmsDeviceIdDeregistered"
      | "KmsDeviceIdRegistered"
      | "KmsInfoSet"
      | "OwnershipTransferred"
      | "TProxyAppIdSet"
  ): EventFragment;

  encodeFunctionData(
    functionFragment: "allowedEnclaves",
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
    functionFragment: "deregisterEnclave",
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
    functionFragment: "registerApp",
    values: [BytesLike, AddressLike]
  ): string;
  encodeFunctionData(
    functionFragment: "registerEnclave",
    values: [BytesLike]
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
    functionFragment: "setKmsInfo",
    values: [KmsAuth.KmsInfoStruct]
  ): string;
  encodeFunctionData(
    functionFragment: "setTProxyAppId",
    values: [AddressLike]
  ): string;
  encodeFunctionData(
    functionFragment: "tproxyAppId",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "transferOwnership",
    values: [AddressLike]
  ): string;

  decodeFunctionResult(
    functionFragment: "allowedEnclaves",
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
    functionFragment: "deregisterEnclave",
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
    functionFragment: "registerApp",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "registerEnclave",
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
  decodeFunctionResult(functionFragment: "setKmsInfo", data: BytesLike): Result;
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

export namespace EnclaveDeregisteredEvent {
  export type InputTuple = [mrEnclave: BytesLike];
  export type OutputTuple = [mrEnclave: string];
  export interface OutputObject {
    mrEnclave: string;
  }
  export type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
  export type Filter = TypedDeferredTopicFilter<Event>;
  export type Log = TypedEventLog<Event>;
  export type LogDescription = TypedLogDescription<Event>;
}

export namespace EnclaveRegisteredEvent {
  export type InputTuple = [mrEnclave: BytesLike];
  export type OutputTuple = [mrEnclave: string];
  export interface OutputObject {
    mrEnclave: string;
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
  export type InputTuple = [tproxyAppId: AddressLike];
  export type OutputTuple = [tproxyAppId: string];
  export interface OutputObject {
    tproxyAppId: string;
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

  allowedEnclaves: TypedContractMethod<[arg0: BytesLike], [boolean], "view">;

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

  deregisterEnclave: TypedContractMethod<
    [mrEnclave: BytesLike],
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
      [string, string, string] & {
        k256Pubkey: string;
        caPubkey: string;
        quote: string;
      }
    ],
    "view"
  >;

  owner: TypedContractMethod<[], [string], "view">;

  registerApp: TypedContractMethod<
    [salt: BytesLike, controller: AddressLike],
    [void],
    "nonpayable"
  >;

  registerEnclave: TypedContractMethod<
    [mrEnclave: BytesLike],
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

  setKmsInfo: TypedContractMethod<
    [info: KmsAuth.KmsInfoStruct],
    [void],
    "nonpayable"
  >;

  setTProxyAppId: TypedContractMethod<
    [appId: AddressLike],
    [void],
    "nonpayable"
  >;

  tproxyAppId: TypedContractMethod<[], [string], "view">;

  transferOwnership: TypedContractMethod<
    [newOwner: AddressLike],
    [void],
    "nonpayable"
  >;

  getFunction<T extends ContractMethod = ContractMethod>(
    key: string | FunctionFragment
  ): T;

  getFunction(
    nameOrSignature: "allowedEnclaves"
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
    nameOrSignature: "deregisterEnclave"
  ): TypedContractMethod<[mrEnclave: BytesLike], [void], "nonpayable">;
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
      [string, string, string] & {
        k256Pubkey: string;
        caPubkey: string;
        quote: string;
      }
    ],
    "view"
  >;
  getFunction(
    nameOrSignature: "owner"
  ): TypedContractMethod<[], [string], "view">;
  getFunction(
    nameOrSignature: "registerApp"
  ): TypedContractMethod<
    [salt: BytesLike, controller: AddressLike],
    [void],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "registerEnclave"
  ): TypedContractMethod<[mrEnclave: BytesLike], [void], "nonpayable">;
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
    nameOrSignature: "setKmsInfo"
  ): TypedContractMethod<[info: KmsAuth.KmsInfoStruct], [void], "nonpayable">;
  getFunction(
    nameOrSignature: "setTProxyAppId"
  ): TypedContractMethod<[appId: AddressLike], [void], "nonpayable">;
  getFunction(
    nameOrSignature: "tproxyAppId"
  ): TypedContractMethod<[], [string], "view">;
  getFunction(
    nameOrSignature: "transferOwnership"
  ): TypedContractMethod<[newOwner: AddressLike], [void], "nonpayable">;

  getEvent(
    key: "AppRegistered"
  ): TypedContractEvent<
    AppRegisteredEvent.InputTuple,
    AppRegisteredEvent.OutputTuple,
    AppRegisteredEvent.OutputObject
  >;
  getEvent(
    key: "EnclaveDeregistered"
  ): TypedContractEvent<
    EnclaveDeregisteredEvent.InputTuple,
    EnclaveDeregisteredEvent.OutputTuple,
    EnclaveDeregisteredEvent.OutputObject
  >;
  getEvent(
    key: "EnclaveRegistered"
  ): TypedContractEvent<
    EnclaveRegisteredEvent.InputTuple,
    EnclaveRegisteredEvent.OutputTuple,
    EnclaveRegisteredEvent.OutputObject
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

  filters: {
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

    "EnclaveDeregistered(bytes32)": TypedContractEvent<
      EnclaveDeregisteredEvent.InputTuple,
      EnclaveDeregisteredEvent.OutputTuple,
      EnclaveDeregisteredEvent.OutputObject
    >;
    EnclaveDeregistered: TypedContractEvent<
      EnclaveDeregisteredEvent.InputTuple,
      EnclaveDeregisteredEvent.OutputTuple,
      EnclaveDeregisteredEvent.OutputObject
    >;

    "EnclaveRegistered(bytes32)": TypedContractEvent<
      EnclaveRegisteredEvent.InputTuple,
      EnclaveRegisteredEvent.OutputTuple,
      EnclaveRegisteredEvent.OutputObject
    >;
    EnclaveRegistered: TypedContractEvent<
      EnclaveRegisteredEvent.InputTuple,
      EnclaveRegisteredEvent.OutputTuple,
      EnclaveRegisteredEvent.OutputObject
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

    "TProxyAppIdSet(address)": TypedContractEvent<
      TProxyAppIdSetEvent.InputTuple,
      TProxyAppIdSetEvent.OutputTuple,
      TProxyAppIdSetEvent.OutputObject
    >;
    TProxyAppIdSet: TypedContractEvent<
      TProxyAppIdSetEvent.InputTuple,
      TProxyAppIdSetEvent.OutputTuple,
      TProxyAppIdSetEvent.OutputObject
    >;
  };
}
