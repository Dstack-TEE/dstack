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
    mrSystem: BytesLike;
    mrImage: BytesLike;
    tcbStatus: string;
    advisoryIds: string[];
  };

  export type AppBootInfoStructOutput = [
    appId: string,
    composeHash: string,
    instanceId: string,
    deviceId: string,
    mrAggregated: string,
    mrSystem: string,
    mrImage: string,
    tcbStatus: string,
    advisoryIds: string[]
  ] & {
    appId: string;
    composeHash: string;
    instanceId: string;
    deviceId: string;
    mrAggregated: string;
    mrSystem: string;
    mrImage: string;
    tcbStatus: string;
    advisoryIds: string[];
  };
}

export interface AppAuthInterface extends Interface {
  getFunction(
    nameOrSignature:
      | "UPGRADE_INTERFACE_VERSION"
      | "addComposeHash"
      | "addDevice"
      | "allowAnyDevice"
      | "allowedComposeHashes"
      | "allowedDeviceIds"
      | "appId"
      | "disableUpgrades"
      | "initialize"
      | "isAppAllowed"
      | "owner"
      | "proxiableUUID"
      | "removeComposeHash"
      | "removeDevice"
      | "renounceOwnership"
      | "setAllowAnyDevice"
      | "transferOwnership"
      | "upgradeToAndCall"
  ): FunctionFragment;

  getEvent(
    nameOrSignatureOrTopic:
      | "AllowAnyDeviceSet"
      | "ComposeHashAdded"
      | "ComposeHashRemoved"
      | "DeviceAdded"
      | "DeviceRemoved"
      | "Initialized"
      | "OwnershipTransferred"
      | "Upgraded"
      | "UpgradesDisabled"
  ): EventFragment;

  encodeFunctionData(
    functionFragment: "UPGRADE_INTERFACE_VERSION",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "addComposeHash",
    values: [BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "addDevice",
    values: [BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "allowAnyDevice",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "allowedComposeHashes",
    values: [BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "allowedDeviceIds",
    values: [BytesLike]
  ): string;
  encodeFunctionData(functionFragment: "appId", values?: undefined): string;
  encodeFunctionData(
    functionFragment: "disableUpgrades",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "initialize",
    values: [AddressLike, AddressLike, boolean, boolean]
  ): string;
  encodeFunctionData(
    functionFragment: "isAppAllowed",
    values: [IAppAuth.AppBootInfoStruct]
  ): string;
  encodeFunctionData(functionFragment: "owner", values?: undefined): string;
  encodeFunctionData(
    functionFragment: "proxiableUUID",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "removeComposeHash",
    values: [BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "removeDevice",
    values: [BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "renounceOwnership",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "setAllowAnyDevice",
    values: [boolean]
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
    functionFragment: "addComposeHash",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "addDevice", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "allowAnyDevice",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "allowedComposeHashes",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "allowedDeviceIds",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "appId", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "disableUpgrades",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "initialize", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "isAppAllowed",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "owner", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "proxiableUUID",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "removeComposeHash",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "removeDevice",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "renounceOwnership",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "setAllowAnyDevice",
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

export namespace AllowAnyDeviceSetEvent {
  export type InputTuple = [allowAny: boolean];
  export type OutputTuple = [allowAny: boolean];
  export interface OutputObject {
    allowAny: boolean;
  }
  export type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
  export type Filter = TypedDeferredTopicFilter<Event>;
  export type Log = TypedEventLog<Event>;
  export type LogDescription = TypedLogDescription<Event>;
}

export namespace ComposeHashAddedEvent {
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

export namespace ComposeHashRemovedEvent {
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

export namespace DeviceAddedEvent {
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

export namespace DeviceRemovedEvent {
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

export namespace UpgradesDisabledEvent {
  export type InputTuple = [];
  export type OutputTuple = [];
  export interface OutputObject {}
  export type Event = TypedContractEvent<InputTuple, OutputTuple, OutputObject>;
  export type Filter = TypedDeferredTopicFilter<Event>;
  export type Log = TypedEventLog<Event>;
  export type LogDescription = TypedLogDescription<Event>;
}

export interface AppAuth extends BaseContract {
  connect(runner?: ContractRunner | null): AppAuth;
  waitForDeployment(): Promise<this>;

  interface: AppAuthInterface;

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

  addComposeHash: TypedContractMethod<
    [composeHash: BytesLike],
    [void],
    "nonpayable"
  >;

  addDevice: TypedContractMethod<[deviceId: BytesLike], [void], "nonpayable">;

  allowAnyDevice: TypedContractMethod<[], [boolean], "view">;

  allowedComposeHashes: TypedContractMethod<
    [arg0: BytesLike],
    [boolean],
    "view"
  >;

  allowedDeviceIds: TypedContractMethod<[arg0: BytesLike], [boolean], "view">;

  appId: TypedContractMethod<[], [string], "view">;

  disableUpgrades: TypedContractMethod<[], [void], "nonpayable">;

  initialize: TypedContractMethod<
    [
      initialOwner: AddressLike,
      _appId: AddressLike,
      _disableUpgrades: boolean,
      _allowAnyDevice: boolean
    ],
    [void],
    "nonpayable"
  >;

  isAppAllowed: TypedContractMethod<
    [bootInfo: IAppAuth.AppBootInfoStruct],
    [[boolean, string] & { isAllowed: boolean; reason: string }],
    "view"
  >;

  owner: TypedContractMethod<[], [string], "view">;

  proxiableUUID: TypedContractMethod<[], [string], "view">;

  removeComposeHash: TypedContractMethod<
    [composeHash: BytesLike],
    [void],
    "nonpayable"
  >;

  removeDevice: TypedContractMethod<
    [deviceId: BytesLike],
    [void],
    "nonpayable"
  >;

  renounceOwnership: TypedContractMethod<[], [void], "nonpayable">;

  setAllowAnyDevice: TypedContractMethod<
    [_allowAnyDevice: boolean],
    [void],
    "nonpayable"
  >;

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
    nameOrSignature: "addComposeHash"
  ): TypedContractMethod<[composeHash: BytesLike], [void], "nonpayable">;
  getFunction(
    nameOrSignature: "addDevice"
  ): TypedContractMethod<[deviceId: BytesLike], [void], "nonpayable">;
  getFunction(
    nameOrSignature: "allowAnyDevice"
  ): TypedContractMethod<[], [boolean], "view">;
  getFunction(
    nameOrSignature: "allowedComposeHashes"
  ): TypedContractMethod<[arg0: BytesLike], [boolean], "view">;
  getFunction(
    nameOrSignature: "allowedDeviceIds"
  ): TypedContractMethod<[arg0: BytesLike], [boolean], "view">;
  getFunction(
    nameOrSignature: "appId"
  ): TypedContractMethod<[], [string], "view">;
  getFunction(
    nameOrSignature: "disableUpgrades"
  ): TypedContractMethod<[], [void], "nonpayable">;
  getFunction(
    nameOrSignature: "initialize"
  ): TypedContractMethod<
    [
      initialOwner: AddressLike,
      _appId: AddressLike,
      _disableUpgrades: boolean,
      _allowAnyDevice: boolean
    ],
    [void],
    "nonpayable"
  >;
  getFunction(
    nameOrSignature: "isAppAllowed"
  ): TypedContractMethod<
    [bootInfo: IAppAuth.AppBootInfoStruct],
    [[boolean, string] & { isAllowed: boolean; reason: string }],
    "view"
  >;
  getFunction(
    nameOrSignature: "owner"
  ): TypedContractMethod<[], [string], "view">;
  getFunction(
    nameOrSignature: "proxiableUUID"
  ): TypedContractMethod<[], [string], "view">;
  getFunction(
    nameOrSignature: "removeComposeHash"
  ): TypedContractMethod<[composeHash: BytesLike], [void], "nonpayable">;
  getFunction(
    nameOrSignature: "removeDevice"
  ): TypedContractMethod<[deviceId: BytesLike], [void], "nonpayable">;
  getFunction(
    nameOrSignature: "renounceOwnership"
  ): TypedContractMethod<[], [void], "nonpayable">;
  getFunction(
    nameOrSignature: "setAllowAnyDevice"
  ): TypedContractMethod<[_allowAnyDevice: boolean], [void], "nonpayable">;
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
    key: "AllowAnyDeviceSet"
  ): TypedContractEvent<
    AllowAnyDeviceSetEvent.InputTuple,
    AllowAnyDeviceSetEvent.OutputTuple,
    AllowAnyDeviceSetEvent.OutputObject
  >;
  getEvent(
    key: "ComposeHashAdded"
  ): TypedContractEvent<
    ComposeHashAddedEvent.InputTuple,
    ComposeHashAddedEvent.OutputTuple,
    ComposeHashAddedEvent.OutputObject
  >;
  getEvent(
    key: "ComposeHashRemoved"
  ): TypedContractEvent<
    ComposeHashRemovedEvent.InputTuple,
    ComposeHashRemovedEvent.OutputTuple,
    ComposeHashRemovedEvent.OutputObject
  >;
  getEvent(
    key: "DeviceAdded"
  ): TypedContractEvent<
    DeviceAddedEvent.InputTuple,
    DeviceAddedEvent.OutputTuple,
    DeviceAddedEvent.OutputObject
  >;
  getEvent(
    key: "DeviceRemoved"
  ): TypedContractEvent<
    DeviceRemovedEvent.InputTuple,
    DeviceRemovedEvent.OutputTuple,
    DeviceRemovedEvent.OutputObject
  >;
  getEvent(
    key: "Initialized"
  ): TypedContractEvent<
    InitializedEvent.InputTuple,
    InitializedEvent.OutputTuple,
    InitializedEvent.OutputObject
  >;
  getEvent(
    key: "OwnershipTransferred"
  ): TypedContractEvent<
    OwnershipTransferredEvent.InputTuple,
    OwnershipTransferredEvent.OutputTuple,
    OwnershipTransferredEvent.OutputObject
  >;
  getEvent(
    key: "Upgraded"
  ): TypedContractEvent<
    UpgradedEvent.InputTuple,
    UpgradedEvent.OutputTuple,
    UpgradedEvent.OutputObject
  >;
  getEvent(
    key: "UpgradesDisabled"
  ): TypedContractEvent<
    UpgradesDisabledEvent.InputTuple,
    UpgradesDisabledEvent.OutputTuple,
    UpgradesDisabledEvent.OutputObject
  >;

  filters: {
    "AllowAnyDeviceSet(bool)": TypedContractEvent<
      AllowAnyDeviceSetEvent.InputTuple,
      AllowAnyDeviceSetEvent.OutputTuple,
      AllowAnyDeviceSetEvent.OutputObject
    >;
    AllowAnyDeviceSet: TypedContractEvent<
      AllowAnyDeviceSetEvent.InputTuple,
      AllowAnyDeviceSetEvent.OutputTuple,
      AllowAnyDeviceSetEvent.OutputObject
    >;

    "ComposeHashAdded(bytes32)": TypedContractEvent<
      ComposeHashAddedEvent.InputTuple,
      ComposeHashAddedEvent.OutputTuple,
      ComposeHashAddedEvent.OutputObject
    >;
    ComposeHashAdded: TypedContractEvent<
      ComposeHashAddedEvent.InputTuple,
      ComposeHashAddedEvent.OutputTuple,
      ComposeHashAddedEvent.OutputObject
    >;

    "ComposeHashRemoved(bytes32)": TypedContractEvent<
      ComposeHashRemovedEvent.InputTuple,
      ComposeHashRemovedEvent.OutputTuple,
      ComposeHashRemovedEvent.OutputObject
    >;
    ComposeHashRemoved: TypedContractEvent<
      ComposeHashRemovedEvent.InputTuple,
      ComposeHashRemovedEvent.OutputTuple,
      ComposeHashRemovedEvent.OutputObject
    >;

    "DeviceAdded(bytes32)": TypedContractEvent<
      DeviceAddedEvent.InputTuple,
      DeviceAddedEvent.OutputTuple,
      DeviceAddedEvent.OutputObject
    >;
    DeviceAdded: TypedContractEvent<
      DeviceAddedEvent.InputTuple,
      DeviceAddedEvent.OutputTuple,
      DeviceAddedEvent.OutputObject
    >;

    "DeviceRemoved(bytes32)": TypedContractEvent<
      DeviceRemovedEvent.InputTuple,
      DeviceRemovedEvent.OutputTuple,
      DeviceRemovedEvent.OutputObject
    >;
    DeviceRemoved: TypedContractEvent<
      DeviceRemovedEvent.InputTuple,
      DeviceRemovedEvent.OutputTuple,
      DeviceRemovedEvent.OutputObject
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

    "UpgradesDisabled()": TypedContractEvent<
      UpgradesDisabledEvent.InputTuple,
      UpgradesDisabledEvent.OutputTuple,
      UpgradesDisabledEvent.OutputObject
    >;
    UpgradesDisabled: TypedContractEvent<
      UpgradesDisabledEvent.InputTuple,
      UpgradesDisabledEvent.OutputTuple,
      UpgradesDisabledEvent.OutputObject
    >;
  };
}
