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

export interface IAppAuthBasicManagementInterface extends Interface {
  getFunction(
    nameOrSignature:
      | "addComposeHash"
      | "addDevice"
      | "removeComposeHash"
      | "removeDevice"
      | "supportsInterface"
  ): FunctionFragment;

  getEvent(
    nameOrSignatureOrTopic:
      | "ComposeHashAdded"
      | "ComposeHashRemoved"
      | "DeviceAdded"
      | "DeviceRemoved"
  ): EventFragment;

  encodeFunctionData(
    functionFragment: "addComposeHash",
    values: [BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "addDevice",
    values: [BytesLike]
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
    functionFragment: "supportsInterface",
    values: [BytesLike]
  ): string;

  decodeFunctionResult(
    functionFragment: "addComposeHash",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "addDevice", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "removeComposeHash",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "removeDevice",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "supportsInterface",
    data: BytesLike
  ): Result;
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

export interface IAppAuthBasicManagement extends BaseContract {
  connect(runner?: ContractRunner | null): IAppAuthBasicManagement;
  waitForDeployment(): Promise<this>;

  interface: IAppAuthBasicManagementInterface;

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

  addComposeHash: TypedContractMethod<
    [composeHash: BytesLike],
    [void],
    "nonpayable"
  >;

  addDevice: TypedContractMethod<[deviceId: BytesLike], [void], "nonpayable">;

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

  supportsInterface: TypedContractMethod<
    [interfaceId: BytesLike],
    [boolean],
    "view"
  >;

  getFunction<T extends ContractMethod = ContractMethod>(
    key: string | FunctionFragment
  ): T;

  getFunction(
    nameOrSignature: "addComposeHash"
  ): TypedContractMethod<[composeHash: BytesLike], [void], "nonpayable">;
  getFunction(
    nameOrSignature: "addDevice"
  ): TypedContractMethod<[deviceId: BytesLike], [void], "nonpayable">;
  getFunction(
    nameOrSignature: "removeComposeHash"
  ): TypedContractMethod<[composeHash: BytesLike], [void], "nonpayable">;
  getFunction(
    nameOrSignature: "removeDevice"
  ): TypedContractMethod<[deviceId: BytesLike], [void], "nonpayable">;
  getFunction(
    nameOrSignature: "supportsInterface"
  ): TypedContractMethod<[interfaceId: BytesLike], [boolean], "view">;

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

  filters: {
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
  };
}
