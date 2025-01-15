/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */
import {
  Contract,
  ContractFactory,
  ContractTransactionResponse,
  Interface,
} from "ethers";
import type { Signer, ContractDeployTransaction, ContractRunner } from "ethers";
import type { NonPayableOverrides } from "../common";
import type { KmsAuth, KmsAuthInterface } from "../KmsAuth";

const _abi = [
  {
    inputs: [],
    stateMutability: "nonpayable",
    type: "constructor",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "address",
        name: "appId",
        type: "address",
      },
    ],
    name: "AppRegistered",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "bytes32",
        name: "mrEnclave",
        type: "bytes32",
      },
    ],
    name: "EnclaveDeregistered",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "bytes32",
        name: "mrEnclave",
        type: "bytes32",
      },
    ],
    name: "EnclaveRegistered",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "bytes32",
        name: "mrImage",
        type: "bytes32",
      },
    ],
    name: "ImageDeregistered",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "bytes32",
        name: "mrImage",
        type: "bytes32",
      },
    ],
    name: "ImageRegistered",
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
    name: "KmsComposeHashDeregistered",
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
    name: "KmsComposeHashRegistered",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "bytes32",
        name: "deviceId",
        type: "bytes32",
      },
    ],
    name: "KmsDeviceIdDeregistered",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "bytes32",
        name: "deviceId",
        type: "bytes32",
      },
    ],
    name: "KmsDeviceIdRegistered",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "bytes",
        name: "k256Pubkey",
        type: "bytes",
      },
    ],
    name: "KmsInfoSet",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "previousOwner",
        type: "address",
      },
      {
        indexed: true,
        internalType: "address",
        name: "newOwner",
        type: "address",
      },
    ],
    name: "OwnershipTransferred",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "string",
        name: "tproxyAppId",
        type: "string",
      },
    ],
    name: "TProxyAppIdSet",
    type: "event",
  },
  {
    inputs: [
      {
        internalType: "bytes32",
        name: "",
        type: "bytes32",
      },
    ],
    name: "allowedEnclaves",
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
    inputs: [
      {
        internalType: "bytes32",
        name: "",
        type: "bytes32",
      },
    ],
    name: "allowedImages",
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
    inputs: [
      {
        internalType: "bytes32",
        name: "",
        type: "bytes32",
      },
    ],
    name: "allowedKmsComposeHashes",
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
    inputs: [
      {
        internalType: "bytes32",
        name: "",
        type: "bytes32",
      },
    ],
    name: "allowedKmsDeviceIds",
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
    inputs: [
      {
        internalType: "address",
        name: "",
        type: "address",
      },
    ],
    name: "apps",
    outputs: [
      {
        internalType: "bool",
        name: "isRegistered",
        type: "bool",
      },
      {
        internalType: "address",
        name: "controller",
        type: "address",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "sender",
        type: "address",
      },
      {
        internalType: "bytes32",
        name: "salt",
        type: "bytes32",
      },
    ],
    name: "calculateAppId",
    outputs: [
      {
        internalType: "address",
        name: "appId",
        type: "address",
      },
    ],
    stateMutability: "pure",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes32",
        name: "mrEnclave",
        type: "bytes32",
      },
    ],
    name: "deregisterEnclave",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes32",
        name: "mrImage",
        type: "bytes32",
      },
    ],
    name: "deregisterImage",
    outputs: [],
    stateMutability: "nonpayable",
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
    name: "deregisterKmsComposeHash",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes32",
        name: "deviceId",
        type: "bytes32",
      },
    ],
    name: "deregisterKmsDeviceId",
    outputs: [],
    stateMutability: "nonpayable",
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
    name: "isKmsAllowed",
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
    name: "kmsInfo",
    outputs: [
      {
        internalType: "bytes",
        name: "k256Pubkey",
        type: "bytes",
      },
      {
        internalType: "bytes",
        name: "caPubkey",
        type: "bytes",
      },
      {
        internalType: "bytes",
        name: "quote",
        type: "bytes",
      },
      {
        internalType: "bytes",
        name: "eventlog",
        type: "bytes",
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
        name: "salt",
        type: "bytes32",
      },
      {
        internalType: "address",
        name: "controller",
        type: "address",
      },
    ],
    name: "registerApp",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes32",
        name: "mrEnclave",
        type: "bytes32",
      },
    ],
    name: "registerEnclave",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes32",
        name: "mrImage",
        type: "bytes32",
      },
    ],
    name: "registerImage",
    outputs: [],
    stateMutability: "nonpayable",
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
    name: "registerKmsComposeHash",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes32",
        name: "deviceId",
        type: "bytes32",
      },
    ],
    name: "registerKmsDeviceId",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        components: [
          {
            internalType: "bytes",
            name: "k256Pubkey",
            type: "bytes",
          },
          {
            internalType: "bytes",
            name: "caPubkey",
            type: "bytes",
          },
          {
            internalType: "bytes",
            name: "quote",
            type: "bytes",
          },
          {
            internalType: "bytes",
            name: "eventlog",
            type: "bytes",
          },
        ],
        internalType: "struct KmsAuth.KmsInfo",
        name: "info",
        type: "tuple",
      },
    ],
    name: "setKmsInfo",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "string",
        name: "appId",
        type: "string",
      },
    ],
    name: "setTProxyAppId",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [],
    name: "tproxyAppId",
    outputs: [
      {
        internalType: "string",
        name: "",
        type: "string",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "newOwner",
        type: "address",
      },
    ],
    name: "transferOwnership",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
] as const;

const _bytecode =
  "0x608060405234801561001057600080fd5b50336000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506129b4806100606000396000f3fe608060405234801561001057600080fd5b506004361061014d5760003560e01c8063652a2997116100c35780638f9c04961161007c5780638f9c0496146103b1578063b5ff9c16146103cd578063d6a38ec1146103e9578063e3392a9b14610405578063f2fde38b14610436578063ff861a34146104525761014d565b8063652a29971461030557806365dea842146103235780637a5a7ad61461033f5780637d0253521461035b57806388a89094146103775780638da5cb5b146103935761014d565b80631bf5b80c116101155780631bf5b80c1461020c5780632fa5aa351461022857806336b18874146102585780633f633adb146102885780634d79da59146102a45780635e30331f146102d45761014d565b806307528a6b14610152578063091770631461016e5780631217a09d1461018f5780631309ec43146101ab57806314e155a4146101dc575b600080fd5b61016c600480360381019061016791906119c3565b610482565b005b610176610576565b6040516101869493929190611a80565b60405180910390f35b6101a960048036038101906101a49190611b3f565b6107b4565b005b6101c560048036038101906101c09190611b7f565b61096a565b6040516101d3929190611bd6565b60405180910390f35b6101f660048036038101906101f191906119c3565b6109bb565b6040516102039190611bff565b60405180910390f35b610226600480360381019061022191906119c3565b6109db565b005b610242600480360381019061023d91906119c3565b610acf565b60405161024f9190611bff565b60405180910390f35b610272600480360381019061026d9190611c1a565b610aef565b60405161027f9190611c5a565b60405180910390f35b6102a2600480360381019061029d91906119c3565b610b2a565b005b6102be60048036038101906102b991906119c3565b610c1e565b6040516102cb9190611bff565b60405180910390f35b6102ee60048036038101906102e99190611c99565b610c3e565b6040516102fc929190611d1b565b60405180910390f35b61030d610d7f565b60405161031a9190611d4b565b60405180910390f35b61033d60048036038101906103389190611ea2565b610e0d565b005b610359600480360381019061035491906119c3565b610ee5565b005b6103756004803603810190610370919061207e565b610fd9565b005b610391600480360381019061038c91906119c3565b611103565b005b61039b6111f7565b6040516103a89190611c5a565b60405180910390f35b6103cb60048036038101906103c691906119c3565b61121b565b005b6103e760048036038101906103e291906119c3565b61130f565b005b61040360048036038101906103fe91906119c3565b611403565b005b61041f600480360381019061041a9190611c99565b6114f7565b60405161042d929190611d1b565b60405180910390f35b610450600480360381019061044b9190611b7f565b611798565b005b61046c600480360381019061046791906119c3565b611959565b6040516104799190611bff565b60405180910390f35b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614610510576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161050790612139565b60405180910390fd5b60016007600083815260200190815260200160002060006101000a81548160ff0219169083151502179055507fabc59888a72fadf11a42b4b1ab60bff4560225cc8a65d1a410bbd97e823bcf018160405161056b9190612168565b60405180910390a150565b6001806000018054610587906121b2565b80601f01602080910402602001604051908101604052809291908181526020018280546105b3906121b2565b80156106005780601f106105d557610100808354040283529160200191610600565b820191906000526020600020905b8154815290600101906020018083116105e357829003601f168201915b505050505090806001018054610615906121b2565b80601f0160208091040260200160405190810160405280929190818152602001828054610641906121b2565b801561068e5780601f106106635761010080835404028352916020019161068e565b820191906000526020600020905b81548152906001019060200180831161067157829003601f168201915b5050505050908060020180546106a3906121b2565b80601f01602080910402602001604051908101604052809291908181526020018280546106cf906121b2565b801561071c5780601f106106f15761010080835404028352916020019161071c565b820191906000526020600020905b8154815290600101906020018083116106ff57829003601f168201915b505050505090806003018054610731906121b2565b80601f016020809104026020016040519081016040528092919081815260200182805461075d906121b2565b80156107aa5780601f1061077f576101008083540402835291602001916107aa565b820191906000526020600020905b81548152906001019060200180831161078d57829003601f168201915b5050505050905084565b60006107c03384610aef565b9050600660008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160009054906101000a900460ff1615610852576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016108499061222f565b60405180910390fd5b6001600660008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160006101000a81548160ff02191690831515021790555081600660008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160016101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055507f0d540ad8f39e07d19909687352b9fa017405d93c91a6760981fbae9cf28bfef78160405161095d9190611c5a565b60405180910390a1505050565b60066020528060005260406000206000915090508060000160009054906101000a900460ff16908060000160019054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905082565b60096020528060005260406000206000915054906101000a900460ff1681565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614610a69576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610a6090612139565b60405180910390fd5b60016009600083815260200190815260200160002060006101000a81548160ff0219169083151502179055507f2a90407c6fcd7c2e2a5e7fd238a1fc6c41ce461f7da1ff6350d0b2243595305481604051610ac49190612168565b60405180910390a150565b60076020528060005260406000206000915054906101000a900460ff1681565b6000808383604051602001610b059291906122b8565b6040516020818303038152906040528051906020012090508060001c91505092915050565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614610bb8576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610baf90612139565b60405180910390fd5b60016008600083815260200190815260200160002060006101000a81548160ff0219169083151502179055507fbb218b24bde6ba405fba71b6e1e123ab350a965dc6ad8fc3e53b3cc00754785881604051610c139190612168565b60405180910390a150565b600a6020528060005260406000206000915054906101000a900460ff1681565b60006060600760008460800135815260200190815260200160002060009054906101000a900460ff16610cac5760006040518060400160405280601381526020017f456e636c617665206e6f7420616c6c6f7765640000000000000000000000000081525091509150610d7a565b600960008460200135815260200190815260200160002060009054906101000a900460ff16610d165760006040518060400160405280601c81526020017f4b4d5320636f6d706f73652068617368206e6f7420616c6c6f7765640000000081525091509150610d7a565b600a60008460600135815260200190815260200160002060009054906101000a900460ff16610d635760006040518060600160405280602981526020016129326029913991509150610d7a565b600160405180602001604052806000815250915091505b915091565b60058054610d8c906121b2565b80601f0160208091040260200160405190810160405280929190818152602001828054610db8906121b2565b8015610e055780601f10610dda57610100808354040283529160200191610e05565b820191906000526020600020905b815481529060010190602001808311610de857829003601f168201915b505050505081565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614610e9b576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610e9290612139565b60405180910390fd5b8060059081610eaa919061249a565b507ffa71be58a57ccbf2fe4e110bc83aa1620e20ff2a30bed5ccac0f1975087906db81604051610eda9190611d4b565b60405180910390a150565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614610f73576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610f6a90612139565b60405180910390fd5b60006008600083815260200190815260200160002060006101000a81548160ff0219169083151502179055507f3177541da10e628041923734a3c8841c1702aa4bc6cdacb818eb704f962e754e81604051610fce9190612168565b60405180910390a150565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614611067576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161105e90612139565b60405180910390fd5b806001600082015181600001908161107f91906125c7565b50602082015181600101908161109591906125c7565b5060408201518160020190816110ab91906125c7565b5060608201518160030190816110c191906125c7565b509050507f77cdad119a452bbd96c45635758fc4af8a6bde3deaccf3fada634ddf9a16270681600001516040516110f89190612699565b60405180910390a150565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614611191576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161118890612139565b60405180910390fd5b6001600a600083815260200190815260200160002060006101000a81548160ff0219169083151502179055507f6bd4d1a278f7fc5fe63a99cf254e598b6c3c069f51ed67564ca6c033d993fd4a816040516111ec9190612168565b60405180910390a150565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16146112a9576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016112a090612139565b60405180910390fd5b60006009600083815260200190815260200160002060006101000a81548160ff0219169083151502179055507fac992076e4ec5fa0a511118a6009763a267afca83446be29e4344393e5de4198816040516113049190612168565b60405180910390a150565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff161461139d576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161139490612139565b60405180910390fd5b6000600a600083815260200190815260200160002060006101000a81548160ff0219169083151502179055507fa54eca6bec89886456df499328bab27fe43544464801ecd8f59fdca31e0268d5816040516113f89190612168565b60405180910390a150565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614611491576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161148890612139565b60405180910390fd5b60006007600083815260200190815260200160002060006101000a81548160ff0219169083151502179055507f87d50cb2fd026429dce80a44f8c241a2a1ecbb8cbd5e2c73f8f32fd3cd4011b8816040516114ec9190612168565b60405180910390a150565b60006060600660008460000160208101906115129190611b7f565b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160009054906101000a900460ff166115a25760006040518060400160405280601281526020017f417070206e6f742072656769737465726564000000000000000000000000000081525091509150611793565b600760008460800135815260200190815260200160002060009054906101000a900460ff161580156115f65750600860008460a00135815260200190815260200160002060009054906101000a900460ff16155b1561161f57600060405180606001604052806024815260200161295b6024913991509150611793565b6000600660008560000160208101906116389190611b7f565b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160019054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff160361170e5760006040518060400160405280601681526020017f41707020636f6e74726f6c6c6572206e6f7420736574000000000000000000008152509250925050611793565b8073ffffffffffffffffffffffffffffffffffffffff1663e3392a9b856040518263ffffffff1660e01b815260040161174791906127b2565b600060405180830381865afa158015611764573d6000803e3d6000fd5b505050506040513d6000823e3d601f19601f8201168201806040525081019061178d9190612869565b92509250505b915091565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614611826576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161181d90612139565b60405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1603611895576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161188c90612911565b60405180910390fd5b60008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050816000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055508173ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a35050565b60086020528060005260406000206000915054906101000a900460ff1681565b6000604051905090565b600080fd5b600080fd5b6000819050919050565b6119a08161198d565b81146119ab57600080fd5b50565b6000813590506119bd81611997565b92915050565b6000602082840312156119d9576119d8611983565b5b60006119e7848285016119ae565b91505092915050565b600081519050919050565b600082825260208201905092915050565b60005b83811015611a2a578082015181840152602081019050611a0f565b60008484015250505050565b6000601f19601f8301169050919050565b6000611a52826119f0565b611a5c81856119fb565b9350611a6c818560208601611a0c565b611a7581611a36565b840191505092915050565b60006080820190508181036000830152611a9a8187611a47565b90508181036020830152611aae8186611a47565b90508181036040830152611ac28185611a47565b90508181036060830152611ad68184611a47565b905095945050505050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000611b0c82611ae1565b9050919050565b611b1c81611b01565b8114611b2757600080fd5b50565b600081359050611b3981611b13565b92915050565b60008060408385031215611b5657611b55611983565b5b6000611b64858286016119ae565b9250506020611b7585828601611b2a565b9150509250929050565b600060208284031215611b9557611b94611983565b5b6000611ba384828501611b2a565b91505092915050565b60008115159050919050565b611bc181611bac565b82525050565b611bd081611b01565b82525050565b6000604082019050611beb6000830185611bb8565b611bf86020830184611bc7565b9392505050565b6000602082019050611c146000830184611bb8565b92915050565b60008060408385031215611c3157611c30611983565b5b6000611c3f85828601611b2a565b9250506020611c50858286016119ae565b9150509250929050565b6000602082019050611c6f6000830184611bc7565b92915050565b600080fd5b600060c08284031215611c9057611c8f611c75565b5b81905092915050565b600060c08284031215611caf57611cae611983565b5b6000611cbd84828501611c7a565b91505092915050565b600081519050919050565b600082825260208201905092915050565b6000611ced82611cc6565b611cf78185611cd1565b9350611d07818560208601611a0c565b611d1081611a36565b840191505092915050565b6000604082019050611d306000830185611bb8565b8181036020830152611d428184611ce2565b90509392505050565b60006020820190508181036000830152611d658184611ce2565b905092915050565b600080fd5b600080fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b611daf82611a36565b810181811067ffffffffffffffff82111715611dce57611dcd611d77565b5b80604052505050565b6000611de1611979565b9050611ded8282611da6565b919050565b600067ffffffffffffffff821115611e0d57611e0c611d77565b5b611e1682611a36565b9050602081019050919050565b82818337600083830152505050565b6000611e45611e4084611df2565b611dd7565b905082815260208101848484011115611e6157611e60611d72565b5b611e6c848285611e23565b509392505050565b600082601f830112611e8957611e88611d6d565b5b8135611e99848260208601611e32565b91505092915050565b600060208284031215611eb857611eb7611983565b5b600082013567ffffffffffffffff811115611ed657611ed5611988565b5b611ee284828501611e74565b91505092915050565b600080fd5b600080fd5b600067ffffffffffffffff821115611f1057611f0f611d77565b5b611f1982611a36565b9050602081019050919050565b6000611f39611f3484611ef5565b611dd7565b905082815260208101848484011115611f5557611f54611d72565b5b611f60848285611e23565b509392505050565b600082601f830112611f7d57611f7c611d6d565b5b8135611f8d848260208601611f26565b91505092915050565b600060808284031215611fac57611fab611eeb565b5b611fb66080611dd7565b9050600082013567ffffffffffffffff811115611fd657611fd5611ef0565b5b611fe284828501611f68565b600083015250602082013567ffffffffffffffff81111561200657612005611ef0565b5b61201284828501611f68565b602083015250604082013567ffffffffffffffff81111561203657612035611ef0565b5b61204284828501611f68565b604083015250606082013567ffffffffffffffff81111561206657612065611ef0565b5b61207284828501611f68565b60608301525092915050565b60006020828403121561209457612093611983565b5b600082013567ffffffffffffffff8111156120b2576120b1611988565b5b6120be84828501611f96565b91505092915050565b7f4f6e6c79206f776e65722063616e2063616c6c20746869732066756e6374696f60008201527f6e00000000000000000000000000000000000000000000000000000000000000602082015250565b6000612123602183611cd1565b915061212e826120c7565b604082019050919050565b6000602082019050818103600083015261215281612116565b9050919050565b6121628161198d565b82525050565b600060208201905061217d6000830184612159565b92915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b600060028204905060018216806121ca57607f821691505b6020821081036121dd576121dc612183565b5b50919050565b7f41707020616c7265616479207265676973746572656400000000000000000000600082015250565b6000612219601683611cd1565b9150612224826121e3565b602082019050919050565b600060208201905081810360008301526122488161220c565b9050919050565b60008160601b9050919050565b60006122678261224f565b9050919050565b60006122798261225c565b9050919050565b61229161228c82611b01565b61226e565b82525050565b6000819050919050565b6122b26122ad8261198d565b612297565b82525050565b60006122c48285612280565b6014820191506122d482846122a1565b6020820191508190509392505050565b60008190508160005260206000209050919050565b60006020601f8301049050919050565b600082821b905092915050565b6000600883026123467fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff82612309565b6123508683612309565b95508019841693508086168417925050509392505050565b6000819050919050565b6000819050919050565b600061239761239261238d84612368565b612372565b612368565b9050919050565b6000819050919050565b6123b18361237c565b6123c56123bd8261239e565b848454612316565b825550505050565b600090565b6123da6123cd565b6123e58184846123a8565b505050565b5b81811015612409576123fe6000826123d2565b6001810190506123eb565b5050565b601f82111561244e5761241f816122e4565b612428846122f9565b81016020851015612437578190505b61244b612443856122f9565b8301826123ea565b50505b505050565b600082821c905092915050565b600061247160001984600802612453565b1980831691505092915050565b600061248a8383612460565b9150826002028217905092915050565b6124a382611cc6565b67ffffffffffffffff8111156124bc576124bb611d77565b5b6124c682546121b2565b6124d182828561240d565b600060209050601f83116001811461250457600084156124f2578287015190505b6124fc858261247e565b865550612564565b601f198416612512866122e4565b60005b8281101561253a57848901518255600182019150602085019450602081019050612515565b868310156125575784890151612553601f891682612460565b8355505b6001600288020188555050505b505050505050565b60008190508160005260206000209050919050565b601f8211156125c2576125938161256c565b61259c846122f9565b810160208510156125ab578190505b6125bf6125b7856122f9565b8301826123ea565b50505b505050565b6125d0826119f0565b67ffffffffffffffff8111156125e9576125e8611d77565b5b6125f382546121b2565b6125fe828285612581565b600060209050601f831160018114612631576000841561261f578287015190505b612629858261247e565b865550612691565b601f19841661263f8661256c565b60005b8281101561266757848901518255600182019150602085019450602081019050612642565b868310156126845784890151612680601f891682612460565b8355505b6001600288020188555050505b505050505050565b600060208201905081810360008301526126b38184611a47565b905092915050565b60006126ca6020840184611b2a565b905092915050565b6126db81611b01565b82525050565b60006126f060208401846119ae565b905092915050565b6127018161198d565b82525050565b60c0820161271860008301836126bb565b61272560008501826126d2565b5061273360208301836126e1565b61274060208501826126f8565b5061274e60408301836126bb565b61275b60408501826126d2565b5061276960608301836126e1565b61277660608501826126f8565b5061278460808301836126e1565b61279160808501826126f8565b5061279f60a08301836126e1565b6127ac60a08501826126f8565b50505050565b600060c0820190506127c76000830184612707565b92915050565b6127d681611bac565b81146127e157600080fd5b50565b6000815190506127f3816127cd565b92915050565b600061280c61280784611df2565b611dd7565b90508281526020810184848401111561282857612827611d72565b5b612833848285611a0c565b509392505050565b600082601f8301126128505761284f611d6d565b5b81516128608482602086016127f9565b91505092915050565b600080604083850312156128805761287f611983565b5b600061288e858286016127e4565b925050602083015167ffffffffffffffff8111156128af576128ae611988565b5b6128bb8582860161283b565b9150509250929050565b7f496e76616c6964206e6577206f776e6572206164647265737300000000000000600082015250565b60006128fb601983611cd1565b9150612906826128c5565b602082019050919050565b6000602082019050818103600083015261292a816128ee565b905091905056fe4b4d53206973206e6f7420616c6c6f77656420746f20626f6f74206f6e2074686973206465766963654e65697468657220656e636c617665206e6f7220696d61676520697320616c6c6f776564a2646970667358221220e6443a2e928433b775972c01b8e64aeff38df1f67c43f5b30bd47129f3f1e80264736f6c63430008130033";

type KmsAuthConstructorParams =
  | [signer?: Signer]
  | ConstructorParameters<typeof ContractFactory>;

const isSuperArgs = (
  xs: KmsAuthConstructorParams
): xs is ConstructorParameters<typeof ContractFactory> => xs.length > 1;

export class KmsAuth__factory extends ContractFactory {
  constructor(...args: KmsAuthConstructorParams) {
    if (isSuperArgs(args)) {
      super(...args);
    } else {
      super(_abi, _bytecode, args[0]);
    }
  }

  override getDeployTransaction(
    overrides?: NonPayableOverrides & { from?: string }
  ): Promise<ContractDeployTransaction> {
    return super.getDeployTransaction(overrides || {});
  }
  override deploy(overrides?: NonPayableOverrides & { from?: string }) {
    return super.deploy(overrides || {}) as Promise<
      KmsAuth & {
        deploymentTransaction(): ContractTransactionResponse;
      }
    >;
  }
  override connect(runner: ContractRunner | null): KmsAuth__factory {
    return super.connect(runner) as KmsAuth__factory;
  }

  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): KmsAuthInterface {
    return new Interface(_abi) as KmsAuthInterface;
  }
  static connect(address: string, runner?: ContractRunner | null): KmsAuth {
    return new Contract(address, _abi, runner) as unknown as KmsAuth;
  }
}
