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
import type { NonPayableOverrides } from "../../common";
import type { KmsAuth, KmsAuthInterface } from "../../contracts/KmsAuth";

const _abi = [
  {
    inputs: [],
    stateMutability: "nonpayable",
    type: "constructor",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "target",
        type: "address",
      },
    ],
    name: "AddressEmptyCode",
    type: "error",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "implementation",
        type: "address",
      },
    ],
    name: "ERC1967InvalidImplementation",
    type: "error",
  },
  {
    inputs: [],
    name: "ERC1967NonPayable",
    type: "error",
  },
  {
    inputs: [],
    name: "FailedCall",
    type: "error",
  },
  {
    inputs: [],
    name: "InvalidInitialization",
    type: "error",
  },
  {
    inputs: [],
    name: "NotInitializing",
    type: "error",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "owner",
        type: "address",
      },
    ],
    name: "OwnableInvalidOwner",
    type: "error",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "account",
        type: "address",
      },
    ],
    name: "OwnableUnauthorizedAccount",
    type: "error",
  },
  {
    inputs: [],
    name: "UUPSUnauthorizedCallContext",
    type: "error",
  },
  {
    inputs: [
      {
        internalType: "bytes32",
        name: "slot",
        type: "bytes32",
      },
    ],
    name: "UUPSUnsupportedProxiableUUID",
    type: "error",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "bytes32",
        name: "mrAggregated",
        type: "bytes32",
      },
    ],
    name: "AggregatedMrDeregistered",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "bytes32",
        name: "mrAggregated",
        type: "bytes32",
      },
    ],
    name: "AggregatedMrRegistered",
    type: "event",
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
        internalType: "uint64",
        name: "version",
        type: "uint64",
      },
    ],
    name: "Initialized",
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
    name: "TproxyAppIdSet",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "implementation",
        type: "address",
      },
    ],
    name: "Upgraded",
    type: "event",
  },
  {
    inputs: [],
    name: "UPGRADE_INTERFACE_VERSION",
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
        internalType: "bytes32",
        name: "",
        type: "bytes32",
      },
    ],
    name: "allowedAggregatedMrs",
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
        internalType: "bytes32",
        name: "mrAggregated",
        type: "bytes32",
      },
    ],
    name: "deregisterAggregatedMr",
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
        internalType: "address",
        name: "initialOwner",
        type: "address",
      },
    ],
    name: "initialize",
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
            name: "mrAggregated",
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
            name: "mrAggregated",
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
    name: "nextAppId",
    outputs: [
      {
        internalType: "address",
        name: "appId",
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
        name: "",
        type: "address",
      },
    ],
    name: "nextAppSequence",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
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
    inputs: [],
    name: "proxiableUUID",
    outputs: [
      {
        internalType: "bytes32",
        name: "",
        type: "bytes32",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes32",
        name: "mrAggregated",
        type: "bytes32",
      },
    ],
    name: "registerAggregatedMr",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
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
    inputs: [],
    name: "renounceOwnership",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes",
        name: "eventlog",
        type: "bytes",
      },
    ],
    name: "setKmsEventlog",
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
        internalType: "bytes",
        name: "quote",
        type: "bytes",
      },
    ],
    name: "setKmsQuote",
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
    name: "setTproxyAppId",
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
  {
    inputs: [
      {
        internalType: "address",
        name: "newImplementation",
        type: "address",
      },
      {
        internalType: "bytes",
        name: "data",
        type: "bytes",
      },
    ],
    name: "upgradeToAndCall",
    outputs: [],
    stateMutability: "payable",
    type: "function",
  },
] as const;

const _bytecode =
  "0x60a06040523060805234801561001457600080fd5b5061001d610022565b6100d4565b7ff0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00805468010000000000000000900460ff16156100725760405163f92ee8a960e01b815260040160405180910390fd5b80546001600160401b03908116146100d15780546001600160401b0319166001600160401b0390811782556040519081527fc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d29060200160405180910390a15b50565b608051611f0a6100fd6000396000818161139b015281816113c4015261150a0152611f0a6000f3fe6080604052600436106101d75760003560e01c8063715018a611610102578063ad3cb1cc11610095578063c5e231b411610064578063c5e231b41461060e578063e3392a9b1461062e578063f2fde38b1461064e578063ff861a341461066e57600080fd5b8063ad3cb1cc14610570578063b5ff9c16146105a1578063b7b556eb146105c1578063c4d66de8146105ee57600080fd5b806388a89094116100d157806388a89094146104c35780638da5cb5b146104e35780638f9c049614610520578063a48444011461054057600080fd5b8063715018a61461044e578063736ede7a146104635780637a5a7ad6146104835780637d025352146104a357600080fd5b806338226c2a1161017a5780634f1ef286116101495780634f1ef286146103c857806352d1902d146103db5780635e30331f146103fe578063652a29971461042c57600080fd5b806338226c2a1461032b5780633849d596146103585780633f633adb146103785780634d79da591461039857600080fd5b806314e155a4116101b657806314e155a41461028b57806317a1d80f146102cb57806318c1ecb2146102eb5780631bf5b80c1461030b57600080fd5b8062e83a65146101dc57806309177063146101fe5780631309ec431461022c575b600080fd5b3480156101e857600080fd5b506101fc6101f73660046117fb565b61069e565b005b34801561020a57600080fd5b506102136106f9565b6040516102239493929190611864565b60405180910390f35b34801561023857600080fd5b5061026c6102473660046118d8565b60056020526000908152604090205460ff81169061010090046001600160a01b031682565b6040805192151583526001600160a01b03909116602083015201610223565b34801561029757600080fd5b506102bb6102a63660046117fb565b60086020526000908152604090205460ff1681565b6040519015158152602001610223565b3480156102d757600080fd5b506101fc6102e63660046118d8565b610935565b3480156102f757600080fd5b506101fc6103063660046119e9565b610a95565b34801561031757600080fd5b506101fc6103263660046117fb565b610aad565b34801561033757600080fd5b50610340610b00565b6040516001600160a01b039091168152602001610223565b34801561036457600080fd5b506101fc610373366004611a26565b610b6e565b34801561038457600080fd5b506101fc6103933660046117fb565b610bb2565b3480156103a457600080fd5b506102bb6103b33660046117fb565b60096020526000908152604090205460ff1681565b6101fc6103d6366004611a6f565b610c05565b3480156103e757600080fd5b506103f0610c20565b604051908152602001610223565b34801561040a57600080fd5b5061041e610419366004611abd565b610c3d565b604051610223929190611ad5565b34801561043857600080fd5b50610441610d4b565b6040516102239190611af0565b34801561045a57600080fd5b506101fc610dd9565b34801561046f57600080fd5b506101fc61047e3660046119e9565b610ded565b34801561048f57600080fd5b506101fc61049e3660046117fb565b610e01565b3480156104af57600080fd5b506101fc6104be366004611b03565b610e51565b3480156104cf57600080fd5b506101fc6104de3660046117fb565b610edf565b3480156104ef57600080fd5b507f9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c199300546001600160a01b0316610340565b34801561052c57600080fd5b506101fc61053b3660046117fb565b610f32565b34801561054c57600080fd5b506102bb61055b3660046117fb565b60066020526000908152604090205460ff1681565b34801561057c57600080fd5b50610441604051806040016040528060058152602001640352e302e360dc1b81525081565b3480156105ad57600080fd5b506101fc6105bc3660046117fb565b610f82565b3480156105cd57600080fd5b506103f06105dc3660046118d8565b600a6020526000908152604090205481565b3480156105fa57600080fd5b506101fc6106093660046118d8565b610fd2565b34801561061a57600080fd5b506101fc6106293660046117fb565b6110ea565b34801561063a57600080fd5b5061041e610649366004611abd565b61113d565b34801561065a57600080fd5b506101fc6106693660046118d8565b6112f7565b34801561067a57600080fd5b506102bb6106893660046117fb565b60076020526000908152604090205460ff1681565b6106a6611335565b60008181526006602052604090819020805460ff19169055517f5ed2cae766a97ae1824da82872566214ec66595770ed66f3cb50d498d8db1df4906106ee9083815260200190565b60405180910390a150565b60008054819061070890611bdc565b80601f016020809104026020016040519081016040528092919081815260200182805461073490611bdc565b80156107815780601f1061075657610100808354040283529160200191610781565b820191906000526020600020905b81548152906001019060200180831161076457829003601f168201915b50505050509080600101805461079690611bdc565b80601f01602080910402602001604051908101604052809291908181526020018280546107c290611bdc565b801561080f5780601f106107e45761010080835404028352916020019161080f565b820191906000526020600020905b8154815290600101906020018083116107f257829003601f168201915b50505050509080600201805461082490611bdc565b80601f016020809104026020016040519081016040528092919081815260200182805461085090611bdc565b801561089d5780601f106108725761010080835404028352916020019161089d565b820191906000526020600020905b81548152906001019060200180831161088057829003601f168201915b5050505050908060030180546108b290611bdc565b80601f01602080910402602001604051908101604052809291908181526020018280546108de90611bdc565b801561092b5780601f106109005761010080835404028352916020019161092b565b820191906000526020600020905b81548152906001019060200180831161090e57829003601f168201915b5050505050905084565b6001600160a01b0381166109905760405162461bcd60e51b815260206004820152601a60248201527f496e76616c696420636f6e74726f6c6c6572206164647265737300000000000060448201526064015b60405180910390fd5b600061099a610b00565b6001600160a01b03811660009081526005602052604090205490915060ff16156109ff5760405162461bcd60e51b8152602060048201526016602482015275105c1c08185b1c9958591e481c9959da5cdd195c995960521b6044820152606401610987565b6001600160a01b0380821660009081526005602090815260408083208054948716610100026001600160a81b031990951694909417600117909355338252600a9052908120805491610a5083611c10565b90915550506040516001600160a01b03821681527f0d540ad8f39e07d19909687352b9fa017405d93c91a6760981fbae9cf28bfef79060200160405180910390a15050565b610a9d611335565b6002610aa98282611c7f565b5050565b610ab5611335565b60008181526008602052604090819020805460ff19166001179055517f2a90407c6fcd7c2e2a5e7fd238a1fc6c41ce461f7da1ff6350d0b22435953054906106ee9083815260200190565b336000818152600a6020908152604080832054905192938493610b509330939101606093841b6bffffffffffffffffffffffff1990811682529290931b9091166014830152602882015260480190565b60408051601f19818403018152919052805160209091012092915050565b610b76611335565b6004610b828282611c7f565b507fc0e19c6705b5bf966b7e6a010fac4ed9cb79252157815bdccaed45fd3749c964816040516106ee9190611af0565b610bba611335565b60008181526007602052604090819020805460ff19166001179055517fbb218b24bde6ba405fba71b6e1e123ab350a965dc6ad8fc3e53b3cc007547858906106ee9083815260200190565b610c0d611390565b610c1682611435565b610aa9828261143d565b6000610c2a6114ff565b50600080516020611eb583398151915290565b608081013560009081526006602052604081205460609060ff16610c9957505060408051808201909152601981527f41676772656761746564204d52206e6f7420616c6c6f776564000000000000006020820152600092909150565b60208084013560009081526008909152604090205460ff16610cf357505060408051808201909152601c81527f4b4d5320636f6d706f73652068617368206e6f7420616c6c6f776564000000006020820152600092909150565b606083013560009081526009602052604090205460ff16610d32576000604051806060016040528060298152602001611e8c6029913991509150915091565b5050604080516020810190915260008152600192909150565b60048054610d5890611bdc565b80601f0160208091040260200160405190810160405280929190818152602001828054610d8490611bdc565b8015610dd15780601f10610da657610100808354040283529160200191610dd1565b820191906000526020600020905b815481529060010190602001808311610db457829003601f168201915b505050505081565b610de1611335565b610deb6000611548565b565b610df5611335565b6003610aa98282611c7f565b610e09611335565b60008181526007602052604090819020805460ff19169055517f3177541da10e628041923734a3c8841c1702aa4bc6cdacb818eb704f962e754e906106ee9083815260200190565b610e59611335565b805181906000908190610e6c9082611c7f565b5060208201516001820190610e819082611c7f565b5060408201516002820190610e969082611c7f565b5060608201516003820190610eab9082611c7f565b505081516040517f77cdad119a452bbd96c45635758fc4af8a6bde3deaccf3fada634ddf9a16270692506106ee9190611af0565b610ee7611335565b60008181526009602052604090819020805460ff19166001179055517f6bd4d1a278f7fc5fe63a99cf254e598b6c3c069f51ed67564ca6c033d993fd4a906106ee9083815260200190565b610f3a611335565b60008181526008602052604090819020805460ff19169055517fac992076e4ec5fa0a511118a6009763a267afca83446be29e4344393e5de4198906106ee9083815260200190565b610f8a611335565b60008181526009602052604090819020805460ff19169055517fa54eca6bec89886456df499328bab27fe43544464801ecd8f59fdca31e0268d5906106ee9083815260200190565b7ff0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a008054600160401b810460ff16159067ffffffffffffffff166000811580156110185750825b905060008267ffffffffffffffff1660011480156110355750303b155b905081158015611043575080155b156110615760405163f92ee8a960e01b815260040160405180910390fd5b845467ffffffffffffffff19166001178555831561108b57845460ff60401b1916600160401b1785555b611094866115b9565b61109c6115ca565b83156110e257845460ff60401b19168555604051600181527fc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d29060200160405180910390a15b505050505050565b6110f2611335565b60008181526006602052604090819020805460ff19166001179055517f4d0e5a3df74b9016e63b2b87a88b85371c1fa39b33ab131de176a0240d714d67906106ee9083815260200190565b6000606060058261115160208601866118d8565b6001600160a01b0316815260208101919091526040016000205460ff166111a5575050604080518082019091526012815271105c1c081b9bdd081c9959da5cdd195c995960721b6020820152600092909150565b608083013560009081526006602052604090205460ff161580156111dd575060a083013560009081526007602052604090205460ff16155b156112065760006040518060600160405280602a8152602001611e62602a913991509150915091565b600060058161121860208701876118d8565b6001600160a01b03908116825260208201929092526040016000205461010090041690508061127c57600060405180604001604052806016815260200175105c1c0818dbdb9d1c9bdb1b195c881b9bdd081cd95d60521b8152509250925050915091565b60405163e3392a9b60e01b81526001600160a01b0382169063e3392a9b906112a8908790600401611d3f565b600060405180830381865afa1580156112c5573d6000803e3d6000fd5b505050506040513d6000823e601f3d908101601f191682016040526112ed9190810190611d9a565b9250925050915091565b6112ff611335565b6001600160a01b03811661132957604051631e4fbdf760e01b815260006004820152602401610987565b61133281611548565b50565b336113677f9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c199300546001600160a01b031690565b6001600160a01b031614610deb5760405163118cdaa760e01b8152336004820152602401610987565b306001600160a01b037f000000000000000000000000000000000000000000000000000000000000000016148061141757507f00000000000000000000000000000000000000000000000000000000000000006001600160a01b031661140b600080516020611eb5833981519152546001600160a01b031690565b6001600160a01b031614155b15610deb5760405163703e46dd60e11b815260040160405180910390fd5b611332611335565b816001600160a01b03166352d1902d6040518163ffffffff1660e01b8152600401602060405180830381865afa925050508015611497575060408051601f3d908101601f1916820190925261149491810190611e2c565b60015b6114bf57604051634c9c8ce360e01b81526001600160a01b0383166004820152602401610987565b600080516020611eb583398151915281146114f057604051632a87526960e21b815260048101829052602401610987565b6114fa83836115d2565b505050565b306001600160a01b037f00000000000000000000000000000000000000000000000000000000000000001614610deb5760405163703e46dd60e11b815260040160405180910390fd5b7f9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c19930080546001600160a01b031981166001600160a01b03848116918217845560405192169182907f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e090600090a3505050565b6115c1611628565b61133281611671565b610deb611628565b6115db82611679565b6040516001600160a01b038316907fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b90600090a2805115611620576114fa82826116de565b610aa9611754565b7ff0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a0054600160401b900460ff16610deb57604051631afcd79f60e31b815260040160405180910390fd5b6112ff611628565b806001600160a01b03163b6000036116af57604051634c9c8ce360e01b81526001600160a01b0382166004820152602401610987565b600080516020611eb583398151915280546001600160a01b0319166001600160a01b0392909216919091179055565b6060600080846001600160a01b0316846040516116fb9190611e45565b600060405180830381855af49150503d8060008114611736576040519150601f19603f3d011682016040523d82523d6000602084013e61173b565b606091505b509150915061174b858383611773565b95945050505050565b3415610deb5760405163b398979f60e01b815260040160405180910390fd5b60608261178857611783826117d2565b6117cb565b815115801561179f57506001600160a01b0384163b155b156117c857604051639996b31560e01b81526001600160a01b0385166004820152602401610987565b50805b9392505050565b8051156117e25780518082602001fd5b60405163d6bda27560e01b815260040160405180910390fd5b60006020828403121561180d57600080fd5b5035919050565b60005b8381101561182f578181015183820152602001611817565b50506000910152565b60008151808452611850816020860160208601611814565b601f01601f19169290920160200192915050565b6080815260006118776080830187611838565b82810360208401526118898187611838565b9050828103604084015261189d8186611838565b905082810360608401526118b18185611838565b979650505050505050565b80356001600160a01b03811681146118d357600080fd5b919050565b6000602082840312156118ea57600080fd5b6117cb826118bc565b634e487b7160e01b600052604160045260246000fd5b6040516080810167ffffffffffffffff8111828210171561192c5761192c6118f3565b60405290565b604051601f8201601f1916810167ffffffffffffffff8111828210171561195b5761195b6118f3565b604052919050565b600067ffffffffffffffff82111561197d5761197d6118f3565b50601f01601f191660200190565b600061199e61199984611963565b611932565b90508281528383830111156119b257600080fd5b828260208301376000602084830101529392505050565b600082601f8301126119da57600080fd5b6117cb8383356020850161198b565b6000602082840312156119fb57600080fd5b813567ffffffffffffffff811115611a1257600080fd5b611a1e848285016119c9565b949350505050565b600060208284031215611a3857600080fd5b813567ffffffffffffffff811115611a4f57600080fd5b8201601f81018413611a6057600080fd5b611a1e8482356020840161198b565b60008060408385031215611a8257600080fd5b611a8b836118bc565b9150602083013567ffffffffffffffff811115611aa757600080fd5b611ab3858286016119c9565b9150509250929050565b600060c08284031215611acf57600080fd5b50919050565b8215158152604060208201526000611a1e6040830184611838565b6020815260006117cb6020830184611838565b600060208284031215611b1557600080fd5b813567ffffffffffffffff80821115611b2d57600080fd5b9083019060808286031215611b4157600080fd5b611b49611909565b823582811115611b5857600080fd5b611b64878286016119c9565b825250602083013582811115611b7957600080fd5b611b85878286016119c9565b602083015250604083013582811115611b9d57600080fd5b611ba9878286016119c9565b604083015250606083013582811115611bc157600080fd5b611bcd878286016119c9565b60608301525095945050505050565b600181811c90821680611bf057607f821691505b602082108103611acf57634e487b7160e01b600052602260045260246000fd5b600060018201611c3057634e487b7160e01b600052601160045260246000fd5b5060010190565b601f8211156114fa576000816000526020600020601f850160051c81016020861015611c605750805b601f850160051c820191505b818110156110e257828155600101611c6c565b815167ffffffffffffffff811115611c9957611c996118f3565b611cad81611ca78454611bdc565b84611c37565b602080601f831160018114611ce25760008415611cca5750858301515b600019600386901b1c1916600185901b1785556110e2565b600085815260208120601f198616915b82811015611d1157888601518255948401946001909101908401611cf2565b5085821015611d2f5787850151600019600388901b60f8161c191681555b5050505050600190811b01905550565b60c081016001600160a01b0380611d55856118bc565b1683526020840135602084015280611d6f604086016118bc565b16604084015250606083013560608301526080830135608083015260a083013560a083015292915050565b60008060408385031215611dad57600080fd5b82518015158114611dbd57600080fd5b602084015190925067ffffffffffffffff811115611dda57600080fd5b8301601f81018513611deb57600080fd5b8051611df961199982611963565b818152866020838501011115611e0e57600080fd5b611e1f826020830160208601611814565b8093505050509250929050565b600060208284031215611e3e57600080fd5b5051919050565b60008251611e57818460208701611814565b919091019291505056fe4e6569746865722061676772656761746564204d52206e6f7220696d61676520697320616c6c6f7765644b4d53206973206e6f7420616c6c6f77656420746f20626f6f74206f6e207468697320646576696365360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbca26469706673582212205a5568606c51ccf50b1718047d2fa26d839b06b8e7e39ffe4824dbd1d6202fa364736f6c63430008160033";

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
