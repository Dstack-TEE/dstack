/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */
import {
  Contract,
  ContractFactory,
  ContractTransactionResponse,
  Interface,
} from "ethers";
import type {
  Signer,
  AddressLike,
  ContractDeployTransaction,
  ContractRunner,
} from "ethers";
import type { NonPayableOverrides } from "../common";
import type { AppAuth, AppAuthInterface } from "../AppAuth";

const _abi = [
  {
    inputs: [
      {
        internalType: "address",
        name: "_appId",
        type: "address",
      },
    ],
    stateMutability: "nonpayable",
    type: "constructor",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "bytes32",
        name: "composeHash",
        type: "bytes32",
      },
    ],
    name: "ComposeHashAdded",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "bytes32",
        name: "composeHash",
        type: "bytes32",
      },
    ],
    name: "ComposeHashRemoved",
    type: "event",
  },
  {
    inputs: [
      {
        internalType: "bytes32",
        name: "composeHash",
        type: "bytes32",
      },
    ],
    name: "addComposeHash",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes32",
        name: "",
        type: "bytes32",
      },
    ],
    name: "allowedComposeHashes",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "appId",
    outputs: [
      {
        internalType: "address",
        name: "",
        type: "address",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
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
  {
    inputs: [],
    name: "owner",
    outputs: [
      {
        internalType: "address",
        name: "",
        type: "address",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes32",
        name: "composeHash",
        type: "bytes32",
      },
    ],
    name: "removeComposeHash",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
] as const;

const _bytecode =
  "0x608060405234801561001057600080fd5b5060405161096e38038061096e8339818101604052810190610032919061011c565b336000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555080600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050610149565b600080fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b60006100e9826100be565b9050919050565b6100f9816100de565b811461010457600080fd5b50565b600081519050610116816100f0565b92915050565b600060208284031215610132576101316100b9565b5b600061014084828501610107565b91505092915050565b610816806101586000396000f3fe608060405234801561001057600080fd5b50600436106100625760003560e01c80632f6622e51461006757806367b3f22c1461009757806380afdea8146100b35780638da5cb5b146100d1578063dfc77223146100ef578063e3392a9b1461010b575b600080fd5b610081600480360381019061007c91906104fb565b61013c565b60405161008e9190610543565b60405180910390f35b6100b160048036038101906100ac91906104fb565b61015c565b005b6100bb610250565b6040516100c8919061059f565b60405180910390f35b6100d9610276565b6040516100e6919061059f565b60405180910390f35b610109600480360381019061010491906104fb565b61029a565b005b610125600480360381019061012091906105de565b61038e565b60405161013392919061069b565b60405180910390f35b60026020528060005260406000206000915054906101000a900460ff1681565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16146101ea576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016101e19061073d565b60405180910390fd5b60006002600083815260200190815260200160002060006101000a81548160ff0219169083151502179055507f755b79bd4b0eeab344d032284a99003b2ddc018b646752ac72d681593a6e894781604051610245919061076c565b60405180910390a150565b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614610328576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161031f9061073d565b60405180910390fd5b60016002600083815260200190815260200160002060006101000a81548160ff0219169083151502179055507ffecb34306dd9d8b785b54d65489d06afc8822a0893ddacedff40c50a4942d0af81604051610383919061076c565b60405180910390a150565b60006060600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168360000160208101906103de91906107b3565b73ffffffffffffffffffffffffffffffffffffffff161461043a5760006040518060400160405280600e81526020017f496e76616c696420617070204944000000000000000000000000000000000000815250915091506104bb565b600260008460200135815260200190815260200160002060009054906101000a900460ff166104a45760006040518060400160405280601881526020017f436f6d706f73652068617368206e6f7420616c6c6f7765640000000000000000815250915091506104bb565b600160405180602001604052806000815250915091505b915091565b600080fd5b6000819050919050565b6104d8816104c5565b81146104e357600080fd5b50565b6000813590506104f5816104cf565b92915050565b600060208284031215610511576105106104c0565b5b600061051f848285016104e6565b91505092915050565b60008115159050919050565b61053d81610528565b82525050565b60006020820190506105586000830184610534565b92915050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b60006105898261055e565b9050919050565b6105998161057e565b82525050565b60006020820190506105b46000830184610590565b92915050565b600080fd5b600060c082840312156105d5576105d46105ba565b5b81905092915050565b600060c082840312156105f4576105f36104c0565b5b6000610602848285016105bf565b91505092915050565b600081519050919050565b600082825260208201905092915050565b60005b8381101561064557808201518184015260208101905061062a565b60008484015250505050565b6000601f19601f8301169050919050565b600061066d8261060b565b6106778185610616565b9350610687818560208601610627565b61069081610651565b840191505092915050565b60006040820190506106b06000830185610534565b81810360208301526106c28184610662565b90509392505050565b7f4f6e6c79206f776e65722063616e2063616c6c20746869732066756e6374696f60008201527f6e00000000000000000000000000000000000000000000000000000000000000602082015250565b6000610727602183610616565b9150610732826106cb565b604082019050919050565b600060208201905081810360008301526107568161071a565b9050919050565b610766816104c5565b82525050565b6000602082019050610781600083018461075d565b92915050565b6107908161057e565b811461079b57600080fd5b50565b6000813590506107ad81610787565b92915050565b6000602082840312156107c9576107c86104c0565b5b60006107d78482850161079e565b9150509291505056fea2646970667358221220f3281dfa79d342c138c5d5f9cdd3d7cc0d70a0c9a7170875895be4802527a05064736f6c63430008130033";

type AppAuthConstructorParams =
  | [signer?: Signer]
  | ConstructorParameters<typeof ContractFactory>;

const isSuperArgs = (
  xs: AppAuthConstructorParams
): xs is ConstructorParameters<typeof ContractFactory> => xs.length > 1;

export class AppAuth__factory extends ContractFactory {
  constructor(...args: AppAuthConstructorParams) {
    if (isSuperArgs(args)) {
      super(...args);
    } else {
      super(_abi, _bytecode, args[0]);
    }
  }

  override getDeployTransaction(
    _appId: AddressLike,
    overrides?: NonPayableOverrides & { from?: string }
  ): Promise<ContractDeployTransaction> {
    return super.getDeployTransaction(_appId, overrides || {});
  }
  override deploy(
    _appId: AddressLike,
    overrides?: NonPayableOverrides & { from?: string }
  ) {
    return super.deploy(_appId, overrides || {}) as Promise<
      AppAuth & {
        deploymentTransaction(): ContractTransactionResponse;
      }
    >;
  }
  override connect(runner: ContractRunner | null): AppAuth__factory {
    return super.connect(runner) as AppAuth__factory;
  }

  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): AppAuthInterface {
    return new Interface(_abi) as AppAuthInterface;
  }
  static connect(address: string, runner?: ContractRunner | null): AppAuth {
    return new Contract(address, _abi, runner) as unknown as AppAuth;
  }
}