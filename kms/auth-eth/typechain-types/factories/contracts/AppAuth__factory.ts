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
import type { AppAuth, AppAuthInterface } from "../../contracts/AppAuth";

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
        internalType: "bool",
        name: "allowAny",
        type: "bool",
      },
    ],
    name: "AllowAnyDeviceSet",
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
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "bytes32",
        name: "deviceId",
        type: "bytes32",
      },
    ],
    name: "DeviceAdded",
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
    name: "DeviceRemoved",
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
    anonymous: false,
    inputs: [],
    name: "UpgradesDisabled",
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
        name: "deviceId",
        type: "bytes32",
      },
    ],
    name: "addDeviceId",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [],
    name: "allowAnyDevice",
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
    inputs: [
      {
        internalType: "bytes32",
        name: "",
        type: "bytes32",
      },
    ],
    name: "allowedDeviceIds",
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
    inputs: [],
    name: "disableUpgrades",
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
      {
        internalType: "address",
        name: "_appId",
        type: "address",
      },
      {
        internalType: "bool",
        name: "_disableUpgrades",
        type: "bool",
      },
      {
        internalType: "bool",
        name: "_allowAnyDevice",
        type: "bool",
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
        name: "composeHash",
        type: "bytes32",
      },
    ],
    name: "removeComposeHash",
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
    name: "removeDeviceId",
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
        internalType: "bool",
        name: "_allowAnyDevice",
        type: "bool",
      },
    ],
    name: "setAllowAnyDevice",
    outputs: [],
    stateMutability: "nonpayable",
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
  "0x60a06040523060805234801561001457600080fd5b5061001d610022565b6100d4565b7ff0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00805468010000000000000000900460ff16156100725760405163f92ee8a960e01b815260040160405180910390fd5b80546001600160401b03908116146100d15780546001600160401b0319166001600160401b0390811782556040519081527fc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d29060200160405180910390a15b50565b60805161114b6100fd600039600081816109be015281816109e70152610b8a015261114b6000f3fe6080604052600436106101095760003560e01c806389287e0a11610095578063bf8b211b11610064578063bf8b211b14610312578063dfc7722314610342578063e3392a9b14610362578063ec66903614610390578063f2fde38b146103a557600080fd5b806389287e0a146102575780638da5cb5b14610277578063ad3cb1cc146102b4578063b51f700c146102f257600080fd5b806352d1902d116100dc57806352d1902d146101a757806367b3f22c146101ca578063715018a6146101ea5780637c4beeb8146101ff57806380afdea81461021f57600080fd5b80630596ced81461010e5780632f6622e5146101305780633440a16a146101755780634f1ef28614610194575b600080fd5b34801561011a57600080fd5b5061012e610129366004610e7b565b6103c5565b005b34801561013c57600080fd5b5061016061014b366004610e7b565b60016020526000908152604090205460ff1681565b60405190151581526020015b60405180910390f35b34801561018157600080fd5b5060025461016090610100900460ff1681565b61012e6101a2366004610ec6565b610423565b3480156101b357600080fd5b506101bc610442565b60405190815260200161016c565b3480156101d657600080fd5b5061012e6101e5366004610e7b565b61045f565b3480156101f657600080fd5b5061012e6104af565b34801561020b57600080fd5b5061012e61021a366004610f98565b6104c3565b34801561022b57600080fd5b5060005461023f906001600160a01b031681565b6040516001600160a01b03909116815260200161016c565b34801561026357600080fd5b5061012e610272366004610fb3565b610514565b34801561028357600080fd5b507f9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c199300546001600160a01b031661023f565b3480156102c057600080fd5b506102e5604051806040016040528060058152602001640352e302e360dc1b81525081565b60405161016c9190611057565b3480156102fe57600080fd5b5061012e61030d366004610e7b565b610700565b34801561031e57600080fd5b5061016061032d366004610e7b565b60036020526000908152604090205460ff1681565b34801561034e57600080fd5b5061012e61035d366004610e7b565b610750565b34801561036e57600080fd5b5061038261037d36600461106a565b6107a3565b60405161016c929190611082565b34801561039c57600080fd5b5061012e6108da565b3480156103b157600080fd5b5061012e6103c03660046110a5565b61091a565b6103cd610958565b60008181526003602052604090819020805460ff19166001179055517f67fc71ab96fe3fa3c6f78e9a00e635d591b7333ce611c0380bc577aac702243b906104189083815260200190565b60405180910390a150565b61042b6109b3565b61043482610a58565b61043e8282610abd565b5050565b600061044c610b7f565b506000805160206110f683398151915290565b610467610958565b60008181526001602052604090819020805460ff19169055517f755b79bd4b0eeab344d032284a99003b2ddc018b646752ac72d681593a6e8947906104189083815260200190565b6104b7610958565b6104c16000610bc8565b565b6104cb610958565b600280548215156101000261ff00199091161790556040517fbb2cdb6c7b362202d40373f87bc4788301cca658f91711ac1662e1ad2cba4a209061041890831515815260200190565b7ff0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a008054600160401b810460ff16159067ffffffffffffffff1660008115801561055a5750825b905060008267ffffffffffffffff1660011480156105775750303b155b905081158015610585575080155b156105a35760405163f92ee8a960e01b815260040160405180910390fd5b845467ffffffffffffffff1916600117855583156105cd57845460ff60401b1916600160401b1785555b6001600160a01b0389166106205760405162461bcd60e51b8152602060048201526015602482015274496e76616c6964206f776e6572206164647265737360581b60448201526064015b60405180910390fd5b6001600160a01b0388166106675760405162461bcd60e51b815260206004820152600e60248201526d125b9d985b1a5908185c1c08125160921b6044820152606401610617565b600080546001600160a01b0319166001600160a01b038a161790556002805461ffff191688151561ff00191617610100881515021790556106a789610c39565b6106af610c4a565b83156106f557845460ff60401b19168555604051600181527fc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d29060200160405180910390a15b505050505050505050565b610708610958565b60008181526003602052604090819020805460ff19169055517fe0862975ac517b0478d308012afabc4bc37c23874a18144d7f2dfb852ff95c2c906104189083815260200190565b610758610958565b600081815260016020818152604092839020805460ff191690921790915590518281527ffecb34306dd9d8b785b54d65489d06afc8822a0893ddacedff40c50a4942d0af9101610418565b600080546060906001600160a01b03166107c060208501856110a5565b6001600160a01b0316146108035750506040805180820190915260148152732bb937b7339030b8381031b7b73a3937b63632b960611b6020820152600092909150565b60208084013560009081526001909152604090205460ff1661085d57505060408051808201909152601881527f436f6d706f73652068617368206e6f7420616c6c6f77656400000000000000006020820152600092909150565b600254610100900460ff161580156108895750606083013560009081526003602052604090205460ff16155b156108c157505060408051808201909152601281527111195d9a58d9481b9bdd08185b1b1bddd95960721b6020820152600092909150565b5050604080516020810190915260008152600192909150565b6108e2610958565b6002805460ff191660011790556040517f0e5daa943fcd7e7182d0e893d180695c2ea9f6f1b4a1c5432faf14cf17b774e890600090a1565b610922610958565b6001600160a01b03811661094c57604051631e4fbdf760e01b815260006004820152602401610617565b61095581610bc8565b50565b3361098a7f9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c199300546001600160a01b031690565b6001600160a01b0316146104c15760405163118cdaa760e01b8152336004820152602401610617565b306001600160a01b037f0000000000000000000000000000000000000000000000000000000000000000161480610a3a57507f00000000000000000000000000000000000000000000000000000000000000006001600160a01b0316610a2e6000805160206110f6833981519152546001600160a01b031690565b6001600160a01b031614155b156104c15760405163703e46dd60e11b815260040160405180910390fd5b610a60610958565b60025460ff16156109555760405162461bcd60e51b815260206004820152602160248201527f557067726164657320617265207065726d616e656e746c792064697361626c656044820152601960fa1b6064820152608401610617565b816001600160a01b03166352d1902d6040518163ffffffff1660e01b8152600401602060405180830381865afa925050508015610b17575060408051601f3d908101601f19168201909252610b14918101906110c0565b60015b610b3f57604051634c9c8ce360e01b81526001600160a01b0383166004820152602401610617565b6000805160206110f68339815191528114610b7057604051632a87526960e21b815260048101829052602401610617565b610b7a8383610c52565b505050565b306001600160a01b037f000000000000000000000000000000000000000000000000000000000000000016146104c15760405163703e46dd60e11b815260040160405180910390fd5b7f9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c19930080546001600160a01b031981166001600160a01b03848116918217845560405192169182907f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e090600090a3505050565b610c41610ca8565b61095581610cf1565b6104c1610ca8565b610c5b82610cf9565b6040516001600160a01b038316907fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b90600090a2805115610ca057610b7a8282610d5e565b61043e610dd4565b7ff0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a0054600160401b900460ff166104c157604051631afcd79f60e31b815260040160405180910390fd5b610922610ca8565b806001600160a01b03163b600003610d2f57604051634c9c8ce360e01b81526001600160a01b0382166004820152602401610617565b6000805160206110f683398151915280546001600160a01b0319166001600160a01b0392909216919091179055565b6060600080846001600160a01b031684604051610d7b91906110d9565b600060405180830381855af49150503d8060008114610db6576040519150601f19603f3d011682016040523d82523d6000602084013e610dbb565b606091505b5091509150610dcb858383610df3565b95945050505050565b34156104c15760405163b398979f60e01b815260040160405180910390fd5b606082610e0857610e0382610e52565b610e4b565b8151158015610e1f57506001600160a01b0384163b155b15610e4857604051639996b31560e01b81526001600160a01b0385166004820152602401610617565b50805b9392505050565b805115610e625780518082602001fd5b60405163d6bda27560e01b815260040160405180910390fd5b600060208284031215610e8d57600080fd5b5035919050565b80356001600160a01b0381168114610eab57600080fd5b919050565b634e487b7160e01b600052604160045260246000fd5b60008060408385031215610ed957600080fd5b610ee283610e94565b9150602083013567ffffffffffffffff80821115610eff57600080fd5b818501915085601f830112610f1357600080fd5b813581811115610f2557610f25610eb0565b604051601f8201601f19908116603f01168101908382118183101715610f4d57610f4d610eb0565b81604052828152886020848701011115610f6657600080fd5b8260208601602083013760006020848301015280955050505050509250929050565b80358015158114610eab57600080fd5b600060208284031215610faa57600080fd5b610e4b82610f88565b60008060008060808587031215610fc957600080fd5b610fd285610e94565b9350610fe060208601610e94565b9250610fee60408601610f88565b9150610ffc60608601610f88565b905092959194509250565b60005b8381101561102257818101518382015260200161100a565b50506000910152565b60008151808452611043816020860160208601611007565b601f01601f19169290920160200192915050565b602081526000610e4b602083018461102b565b600060c0828403121561107c57600080fd5b50919050565b821515815260406020820152600061109d604083018461102b565b949350505050565b6000602082840312156110b757600080fd5b610e4b82610e94565b6000602082840312156110d257600080fd5b5051919050565b600082516110eb818460208701611007565b919091019291505056fe360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbca2646970667358221220c42ce99788059b3355852e0b1ec9c92f07d5ee93b962954841876b29f6e2176964736f6c63430008160033";

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
    overrides?: NonPayableOverrides & { from?: string }
  ): Promise<ContractDeployTransaction> {
    return super.getDeployTransaction(overrides || {});
  }
  override deploy(overrides?: NonPayableOverrides & { from?: string }) {
    return super.deploy(overrides || {}) as Promise<
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
