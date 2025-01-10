/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import { Contract, Interface, type ContractRunner } from "ethers";
import type { IAppAuth, IAppAuthInterface } from "../IAppAuth";

const _abi = [
  {
    inputs: [
      {
        components: [
          {
            internalType: "address",
            name: "appId",
            type: "address",
          },
          {
            internalType: "bytes32",
            name: "composeHash",
            type: "bytes32",
          },
          {
            internalType: "address",
            name: "instanceId",
            type: "address",
          },
          {
            internalType: "bytes32",
            name: "deviceId",
            type: "bytes32",
          },
          {
            internalType: "bytes32",
            name: "mrEnclave",
            type: "bytes32",
          },
          {
            internalType: "bytes32",
            name: "mrImage",
            type: "bytes32",
          },
        ],
        internalType: "struct IAppAuth.AppBootInfo",
        name: "bootInfo",
        type: "tuple",
      },
    ],
    name: "isAppAllowed",
    outputs: [
      {
        internalType: "bool",
        name: "isAllowed",
        type: "bool",
      },
      {
        internalType: "string",
        name: "reason",
        type: "string",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
] as const;

export class IAppAuth__factory {
  static readonly abi = _abi;
  static createInterface(): IAppAuthInterface {
    return new Interface(_abi) as IAppAuthInterface;
  }
  static connect(address: string, runner?: ContractRunner | null): IAppAuth {
    return new Contract(address, _abi, runner) as unknown as IAppAuth;
  }
}