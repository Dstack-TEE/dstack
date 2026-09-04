// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
// SPDX-License-Identifier: Apache-2.0

declare const Vue: any;
const { ref, computed, watch, onMounted } = Vue;
import type { vmm as VmmTypes } from '../proto/vmm_rpc';

// Types based on Rust definitions
type VmConfiguration = VmmTypes.IVmConfiguration;

type AppCompose = {
  manifest_version: number | string;
  name: string;
  features: string[];
  runner: string;
  docker_compose_file?: string;
  public_logs: boolean;
  public_sysinfo: boolean;
  public_tcbinfo: boolean;
  kms_enabled: boolean;
  gateway_enabled: boolean;
  tproxy_enabled?: boolean;
  local_key_provider_enabled: boolean;
  key_provider?: KeyProviderKind;
  key_provider_id: string;
  allowed_envs: string[];
  no_instance_id: boolean;
  secure_time: boolean;
  requirements?: Requirements;
  storage_fs?: string;
  swap_size: number;
  launch_token_hash?: string;
  pre_launch_script?: string;
  init_script?: string | string[];
  event_log_version?: number;
};

function initScriptList(initScript: string | string[] | undefined): string[] {
  const scripts = Array.isArray(initScript)
    ? [...initScript]
    : initScript
      ? [initScript]
      : [];
  return scripts.length > 0 ? scripts : [''];
}

function nonEmptyInitScripts(initScripts: string[]): string[] {
  return initScripts.filter((script) => script.trim());
}

function compatibleInitScripts(initScripts: string[]): string | string[] | undefined {
  const scripts = nonEmptyInitScripts(initScripts);
  return scripts.length === 0 ? undefined : scripts.length === 1 ? scripts[0] : scripts;
}

type KeyProviderKind = 'none' | 'kms' | 'local' | 'tpm';
type RequirementPlatform =
  | 'dstack-tdx'
  | 'dstack-gcp-tdx'
  | 'dstack-amd-sev-snp'
  | 'dstack-nitro-enclave';
type Requirements = {
  platforms?: RequirementPlatform[];
  tdx_measure_acpi_tables?: boolean;
  launch_token_hash?: string;
};

const x25519 = require('../lib/x25519.js');
const { getVmmRpcClient } = require('../lib/vmmRpcClient');

const vmmRpc = getVmmRpcClient();

// System menu state
const systemMenu = ref({
  show: false,
});
const devMode = ref(localStorage.getItem('devMode') === 'true');

type MemoryUnit = 'MB' | 'GB';

type JsonRpcCall = (method: string, params?: Record<string, unknown>) => Promise<Response>;
type Ref<T> = { value: T };

type VmListItem = {
  id: string;
  name: string;
  app_id: string;
  status: string;
  app_url?: string;
  uptime?: string;
  boot_progress?: string;
  shutdown_progress?: string;
  image_version?: string;
  interfaces?: VmmTypes.INetworkInterfaceStatus[];
  running?: boolean;
  configuration?: VmConfiguration;
  appCompose?: AppCompose;
};

type EncryptedEnvEntry = {
  key: string;
  value: string;
};

type PortFormEntry = {
  protocol: string;
  host_address?: string;
  host_port?: number | null;
  vm_port?: number | null;
  /**
   * Which NIC this mapping's traffic enters through. Unset lets the VMM pick.
   * Carried through edits unchanged: `GetInfo` reports it and this form sends
   * the whole list back, so dropping it here would silently unpin a mapping
   * whenever anyone touched an unrelated field.
   */
  // `v-model.number` leaves the raw string here when it does not parse, so
  // an emptied box is `''` rather than `null`. See `normalizePorts`.
  nic_index?: number | string | null;
};

type NetworkFormEntry = {
  mode: string;
  bridge_name?: string;
  /** Pinned at deployment for macvtap NICs; carried through edits unchanged. */
  parent?: string;
  /** '' inherits the node default, otherwise 'on' or 'off'. */
  vhost?: string;
  /**
   * '' lets the queue count follow the vCPU count. A `number` once the operator
   * types into the input: `v-model` casts for `<input type="number">`.
   */
  queues?: string | number;
};

type VmFormState = {
  name: string;
  image: string;
  dockerComposeFile: string;
  initScripts: string[];
  preLaunchScript: string;
  vcpu: number;
  memory: number;
  memoryValue: number;
  memoryUnit: MemoryUnit;
  swap_size: number;
  swapValue: number;
  swapUnit: MemoryUnit;
  disk_size: number;
  selectedGpus: string[];
  attachAllGpus: boolean;
  ports: PortFormEntry[];
  encryptedEnvs: EncryptedEnvEntry[];
  storage_fs: string;
  app_id: string | null;
  key_provider?: KeyProviderKind;
  key_provider_id: string;
  gateway_enabled: boolean;
  public_logs: boolean;
  public_sysinfo: boolean;
  public_tcbinfo: boolean;
  no_tee: boolean;
  simulated_tee: string;
  pin_numa: boolean;
  hugepages: boolean;
  networks: NetworkFormEntry[];
  user_config: string;
  kms_urls: string[];
  gateway_urls: string[];
  stopped: boolean;
  event_log_version: number;
};

type UpdateDialogState = {
  show: boolean;
  vm: VmListItem | null;
  updateCompose: boolean;
  dockerComposeFile: string;
  initScripts: string[];
  preLaunchScript: string;
  encryptedEnvs: EncryptedEnvEntry[];
  resetSecrets: boolean;
  vcpu: number;
  memory: number;
  memoryValue: number;
  memoryUnit: MemoryUnit;
  swap_size: number;
  swapValue: number;
  swapUnit: MemoryUnit;
  disk_size: number;
  image: string;
  ports: PortFormEntry[];
  /// What the dialog opened with, normalized, so the update can tell whether
  /// this request moved the port mappings at all.
  originalPorts: VmmTypes.IPortMapping[];
  attachAllGpus: boolean;
  selectedGpus: string[];
  updateGpuConfig: boolean;
  updateNetworking: boolean;
  networks: NetworkFormEntry[];
  user_config: string;
};

type CloneConfigDialogState = {
  show: boolean;
  name: string;
  compose_file: string;
  image: string;
  vcpu: number;
  memory: number;
  disk_size: number;
  ports: PortFormEntry[];
  user_config: string;
  gpus?: VmmTypes.IGpuConfig;
  kms_urls?: string[];
  gateway_urls?: string[];
  networks?: NetworkFormEntry[];
  hugepages: boolean;
  pin_numa: boolean;
  no_tee: boolean;
  simulated_tee: string;
  encrypted_env?: Uint8Array;
  app_id?: string;
  stopped: boolean;
};

function createVmFormState(preLaunchScript: string): VmFormState {
  return {
    name: '',
    image: '',
    dockerComposeFile: '',
    initScripts: [''],
    preLaunchScript,
    vcpu: 1,
    memory: 2048,
    memoryValue: 2,
    memoryUnit: 'GB',
    swap_size: 0,
    swapValue: 0,
    swapUnit: 'GB',
    disk_size: 20,
    selectedGpus: [],
    attachAllGpus: false,
    ports: [],
    encryptedEnvs: [],
    storage_fs: '',
    app_id: null,
    key_provider: 'kms',
    key_provider_id: '',
    gateway_enabled: true,
    public_logs: true,
    public_sysinfo: true,
    public_tcbinfo: true,
    no_tee: false,
    simulated_tee: '',
    pin_numa: false,
    hugepages: false,
    networks: [],
    user_config: '',
    kms_urls: [],
    gateway_urls: [],
    stopped: false,
    event_log_version: 1,
  };
}

function createUpdateDialogState(): UpdateDialogState {
  return {
    show: false,
    vm: null,
    updateCompose: false,
    dockerComposeFile: '',
    initScripts: [''],
    preLaunchScript: '',
    encryptedEnvs: [],
    resetSecrets: false,
    vcpu: 0,
    memory: 0,
    memoryValue: 0,
    memoryUnit: 'MB',
    swap_size: 0,
    swapValue: 0,
    swapUnit: 'GB',
    disk_size: 0,
    image: '',
    ports: [],
    originalPorts: [],
    attachAllGpus: false,
    selectedGpus: [],
    updateGpuConfig: false,
    updateNetworking: false,
    networks: [],
    user_config: '',
  };
}

function createCloneConfigDialogState(): CloneConfigDialogState {
  return {
    show: false,
    name: '',
    compose_file: '',
    image: '',
    vcpu: 0,
    memory: 0,
    disk_size: 0,
    ports: [],
    user_config: '',
    gpus: undefined,
    kms_urls: undefined,
    gateway_urls: undefined,
    networks: undefined,
    hugepages: false,
    pin_numa: false,
    no_tee: false,
    simulated_tee: '',
    encrypted_env: undefined,
    app_id: undefined,
    stopped: false,
  };
}

function useVmManager() {
  const version = ref({ version: '-', commit: '' });
  const vms = ref([] as VmListItem[]);
  const expandedVMs = ref(new Set() as Set<string>);
  const networkInfo = ref({} as Record<string, any>);
  const searchQuery = ref('');
  const currentPage = ref(1);
  const pageInput = ref(1);
  const pageSize = ref(Number.parseInt(localStorage.getItem('pageSize') || '50', 10));
  const totalVMs = ref(0);
  const hasMorePages = ref(false);
  const loadingVMDetails = ref(false);
  const maxPage = computed(() => Math.ceil(totalVMs.value / pageSize.value) || 1);

  const preLaunchScript = `
EXPECTED_TOKEN_HASH=$(jq -j .launch_token_hash app-compose.json)
if [ "$EXPECTED_TOKEN_HASH" == "null" ]; then
    echo "Skipped APP_LAUNCH_TOKEN check"
else
  ACTUAL_TOKEN_HASH=$(echo -n "$APP_LAUNCH_TOKEN" | sha256sum | cut -d' ' -f1)
  if [ "$EXPECTED_TOKEN_HASH" != "$ACTUAL_TOKEN_HASH" ]; then
      echo "Error: Incorrect APP_LAUNCH_TOKEN, please make sure set the correct APP_LAUNCH_TOKEN in env"
      reboot
      exit 1
  else
      echo "APP_LAUNCH_TOKEN checked OK"
  fi
fi
`;

  const vmForm: Ref<VmFormState> = ref(createVmFormState(preLaunchScript));

  const availableImages = ref([] as Array<{ name: string; version?: string }>);
  const availableGpus = ref([] as Array<any>);
  const availableGpuProducts = ref([] as Array<any>);
  const allowAttachAllGpus = ref(false);

  const updateDialog: Ref<UpdateDialogState> = ref(createUpdateDialogState());

  const updateMessage = ref('');
  const successMessage = ref('');
  const errorMessage = ref('');

  const cloneConfigDialog: Ref<CloneConfigDialogState> = ref(createCloneConfigDialogState());

  const showCreateDialog = ref(false);
  const config = ref({
    portMappingEnabled: false,
    networking: null as VmmTypes.INetworkingCapabilities | null,
  });
  const networkingModes = computed(() => {
    const supported = config.value.networking?.supported_modes || [];
    const fallback = supported.length > 0 ? supported : ['user'];
    return Array.from(new Set(fallback));
  });
  const defaultBridge = computed(() => config.value.networking?.default_bridge || '');
  const maxNetQueues = computed(() => config.value.networking?.max_queues || 0);
  const defaultVhostOn = computed(() => !!config.value.networking?.default_vhost);
  // Whether the node's own default backend can carry vhost-net and multiqueue.
  // The RPC accepts the two tuning fields on a mode-less entry regardless --
  // deliberately, so a NIC that inherits its backend stays tunable across a node
  // change -- but on a node whose default is user or custom they lie dormant,
  // and an operator who sets them deserves to be told that rather than discover
  // it in the interfaces panel afterwards.
  const defaultModeTunable = computed(() => {
    const mode = config.value.networking?.default_mode || '';
    return mode === 'bridge' || mode === 'macvtap';
  });
  const defaultNetworkingLabel = computed(() => {
    const mode = config.value.networking?.default_mode || '';
    if (mode === 'bridge') {
      return defaultBridge.value
        ? `Default: Bridge (${defaultBridge.value})`
        : 'Default: Bridge (no default bridge configured)';
    }
    if (mode === 'user') {
      return 'Default: User networking';
    }
    return mode ? `Default: ${networkModeLabel(mode)}` : 'Default: node configuration';
  });
  const composeHashPreview = ref('');
  const updateComposeHashPreview = ref('');

  const BYTES_PER_MB = 1024 * 1024;

  function convertMemoryToMB(value: number, unit: string) {
    if (!Number.isFinite(value) || value < 0) {
      return 0;
    }
    if (unit === 'GB') {
      return value * 1024;
    }
    return value;
  }

  function convertSwapToBytes(value: number, unit: string) {
    const mb = convertMemoryToMB(value, unit);
    if (!Number.isFinite(mb) || mb <= 0) {
      return 0;
    }
    return Math.max(0, Math.round(mb * BYTES_PER_MB));
  }

  function bytesToMB(bytes: number) {
    if (!bytes) {
      return 0;
    }
    return bytes / BYTES_PER_MB;
  }

  function hexToBytes(hex: string) {
    if (!hex) {
      return new Uint8Array();
    }
    const normalized = hex.startsWith('0x') ? hex.slice(2) : hex;
    const length = Math.floor(normalized.length / 2);
    const result = new Uint8Array(length);
    for (let i = 0; i < length; i += 1) {
      const byte = normalized.slice(i * 2, i * 2 + 2);
      result[i] = Number.parseInt(byte, 16);
    }
    return result;
  }

  const clonePortMappings = (ports: VmmTypes.IPortMapping[] = []): PortFormEntry[] =>
    ports.map((port) => ({
      protocol: port.protocol || 'tcp',
      host_address: port.host_address || '127.0.0.1',
      host_port: typeof port.host_port === 'number' ? port.host_port : null,
      vm_port: typeof port.vm_port === 'number' ? port.vm_port : null,
      nic_index: typeof port.nic_index === 'number' ? port.nic_index : null,
    }));

  const normalizePorts = (ports: PortFormEntry[] = []): VmmTypes.IPortMapping[] =>
    ports
      .map((port) => {
        const protocol = (port.protocol || '').trim();
        const hostPort =
          port.host_port === null || port.host_port === undefined ? Number.NaN : Number(port.host_port);
        const vmPort =
          port.vm_port === null || port.vm_port === undefined ? Number.NaN : Number(port.vm_port);
        // An unpinned mapping must stay unpinned rather than become NIC 0:
        // the VMM's own default is the first user-mode NIC, not the first NIC.
        // `v-model.number` hands back the raw string when it does not parse,
        // so a box the operator cleared arrives as `''`. `Number('')` is 0,
        // which would pin to NIC 0 the mapping they just unpinned.
        const nicIndex =
          port.nic_index === null || port.nic_index === undefined || port.nic_index === ''
            ? undefined
            : Number(port.nic_index);
        return {
          protocol,
          host_address: (port.host_address || '127.0.0.1').trim() || '127.0.0.1',
          host_port: hostPort,
          vm_port: vmPort,
          ...(Number.isInteger(nicIndex) && (nicIndex as number) >= 0
            ? { nic_index: nicIndex }
            : {}),
        };
      })
      .filter(
        (port) =>
          port.protocol.length > 0 &&
          Number.isFinite(port.host_port) &&
          Number.isFinite(port.vm_port),
      );

  const cloneNetworks = (configuration?: VmConfiguration | null): NetworkFormEntry[] => {
    const configured = configuration?.networks && configuration.networks.length > 0
      ? configuration.networks
      : (configuration?.networking ? [configuration.networking] : []);
    return configured.map((network) => ({
      mode: network.mode || '',
      bridge_name: network.bridge_name || '',
      parent: network.parent || '',
      vhost: network.vhost === null || network.vhost === undefined ? '' : (network.vhost ? 'on' : 'off'),
      queues: network.queues ? String(network.queues) : '',
    }));
  };

  // Queue pairs, whatever shape the model is in.
  //
  // Not a string: Vue's `v-model` casts for `<input type="number">`, so this
  // field is a `string` while it holds a value loaded from `GetInfo` and a
  // `number` the moment the operator types into it. Assuming either one is how
  // this threw a `TypeError` out of every deploy that set a queue count.
  //
  // The number input already refuses everything but a numeric literal, and the
  // cast turns `2.7` into `2.7` rather than into `parseInt`'s `2`, so what is
  // left to check is that the value is a whole number at least one. The node's
  // cap is deliberately *not* checked here: the server widens it by whatever a
  // VM already holds, so a client-side copy would refuse an update the server
  // accepts and leave that VM's networking uneditable.
  const parseQueueCount = (raw: unknown, label: string): number | undefined => {
    if (raw === null || raw === undefined || raw === '') {
      return undefined;
    }
    const queues = typeof raw === 'number' ? raw : Number(String(raw).trim());
    if (!Number.isInteger(queues) || queues < 1) {
      throw new Error(`${label}: queue pairs must be a whole number of at least 1, or empty to follow the vCPU count; got '${raw}'`);
    }
    return queues;
  };

  // Nothing is filtered out. A mode-less entry is the "keep the node's backend,
  // change only the data plane" override the RPC accepts, and is what a VM
  // deployed that way reports back; dropping it would delete a NIC and renumber
  // the ones after it, which changes their MAC addresses.
  // A row added here starts with no mode, which the RPC reads as "keep the
  // node's backend" rather than as a missing field, so the only way to reach an
  // entry it refuses is to empty a loaded one's bridge or parent, and that
  // earns an error rather than silence.
  const normalizeNetworks = (networks: NetworkFormEntry[] = []): VmmTypes.INetworkingConfig[] =>
    networks
      .map((network, index) => {
        // Leave vhost and queues unset unless the operator picked something, so
        // the node keeps owning them and can still change them later.
        const entry: VmmTypes.INetworkingConfig = {
          mode: (network.mode || '').trim(),
          bridge_name: network.mode === 'bridge' ? (network.bridge_name || '').trim() : '',
          parent: network.mode === 'macvtap' ? (network.parent || '').trim() : '',
        };
        // The tuning controls are hidden for user mode, so sending values the
        // operator cannot see would fail the deploy with nothing to fix.
        if (network.mode !== 'user') {
          if (network.vhost === 'on' || network.vhost === 'off') {
            entry.vhost = network.vhost === 'on';
          }
          const queues = parseQueueCount(network.queues, `network ${index + 1}`);
          if (queues !== undefined) {
            entry.queues = queues;
          }
        }
        return entry;
      });

  function networkModeLabel(mode?: string | null) {
    if (!mode) {
      return 'Default';
    }
    return mode.charAt(0).toUpperCase() + mode.slice(1);
  }

  function deriveGpuSelection(gpuConfig?: VmmTypes.IGpuConfig) {
    if (!gpuConfig) {
      return { attachAll: false, selected: [] as string[] };
    }
    if (gpuConfig.attach_mode === 'all') {
      return { attachAll: true, selected: [] as string[] };
    }
    return {
      attachAll: false,
      selected: (gpuConfig.gpus || []).map((gpu) => gpu.slot).filter(Boolean) as string[],
    };
  }

  function recordError(context: string, err: unknown) {
    console.error(context, err);
    if (err instanceof Error && err.message) {
      errorMessage.value = err.message;
    } else {
      errorMessage.value = String(err);
    }
  }

  function configGpu(form: { attachAllGpus: boolean; selectedGpus: string[] }, isUpdate: boolean = false): VmmTypes.IGpuConfig | undefined {
    if (form.attachAllGpus) {
      return { attach_mode: 'all' };
    }
    // For updates, always return a config when GPUs are being explicitly updated
    // Empty array means no GPUs should be attached
    if (isUpdate) {
      return {
        attach_mode: 'listed',
        gpus: (form.selectedGpus || []).map((slot: string) => ({ slot })),
      };
    }
    // For creation, return undefined if no GPUs are selected
    if (form.selectedGpus && form.selectedGpus.length > 0) {
      return {
        attach_mode: 'listed',
        gpus: form.selectedGpus.map((slot: string) => ({ slot })),
      };
    }
    return undefined;
  }

type CreateVmPayloadSource = {
  name: string;
  image: string;
    compose_file: string;
    vcpu: number;
    memory: number;
    disk_size: number;
    ports: PortFormEntry[];
    encrypted_env?: Uint8Array;
    app_id?: string | null;
    user_config?: string;
  hugepages?: boolean;
  pin_numa?: boolean;
  no_tee?: boolean;
  simulated_tee?: string;
  networks?: NetworkFormEntry[];
    gpus?: VmmTypes.IGpuConfig;
    kms_urls?: string[];
    gateway_urls?: string[];
    stopped?: boolean;
  };

  function buildCreateVmPayload(source: CreateVmPayloadSource): VmmTypes.IVmConfiguration {
    const normalizedPorts = normalizePorts(source.ports);
    const normalizedNetworks = normalizeNetworks(source.networks || []);
    return {
      name: source.name.trim(),
      image: source.image.trim(),
      compose_file: source.compose_file,
      vcpu: Math.max(1, Number(source.vcpu) || 1),
      memory: Math.max(0, Number(source.memory) || 0),
      disk_size: Math.max(0, Number(source.disk_size) || 0),
      ports: normalizedPorts,
      encrypted_env: source.encrypted_env,
      app_id: source.app_id || undefined,
      user_config: source.user_config || '',
      hugepages: !!source.hugepages,
      pin_numa: !!source.pin_numa,
      no_tee: source.no_tee ?? false,
      simulated_tee: source.simulated_tee || undefined,
      networks: normalizedNetworks,
      gpus: source.gpus,
      kms_urls: source.kms_urls?.filter((url) => url && url.trim().length) ?? [],
      gateway_urls: source.gateway_urls?.filter((url) => url && url.trim().length) ?? [],
      stopped: !!source.stopped,
    };
  }

  const autoMemoryDisplay = (mb: number): { memoryValue: number; memoryUnit: MemoryUnit } => {
    if (mb >= 1024) {
      return {
        memoryValue: Number((mb / 1024).toFixed(1)),
        memoryUnit: 'GB',
      };
    }
    return {
      memoryValue: mb,
      memoryUnit: 'MB',
    };
  };

  watch([() => vmForm.value.memoryValue, () => vmForm.value.memoryUnit], () => {
    vmForm.value.memory = convertMemoryToMB(vmForm.value.memoryValue, vmForm.value.memoryUnit);
  });

  watch([() => vmForm.value.swapValue, () => vmForm.value.swapUnit], () => {
    vmForm.value.swap_size = convertSwapToBytes(vmForm.value.swapValue, vmForm.value.swapUnit);
  });

  watch([() => updateDialog.value.memoryValue, () => updateDialog.value.memoryUnit], () => {
    updateDialog.value.memory = convertMemoryToMB(updateDialog.value.memoryValue, updateDialog.value.memoryUnit);
  });

  watch([() => updateDialog.value.swapValue, () => updateDialog.value.swapUnit], () => {
    updateDialog.value.swap_size = convertSwapToBytes(updateDialog.value.swapValue, updateDialog.value.swapUnit);
  });

  function makeBaseUrl(pathname: string) {
    return `${pathname}?json`;
  }

  async function baseRpcCall(pathname: string, params: Record<string, unknown> = {}) {
    const response = await fetch(makeBaseUrl(pathname), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(params),
    });
    if (!response.ok) {
      const error = await response.text();
      errorMessage.value = error;
      throw new Error(error);
    }
    return response;
  }

  const guestRpcCall: JsonRpcCall = (method, params) => baseRpcCall(`/guest/${method}`, params);

  async function loadVMList() {
    try {
      const request: VmmTypes.IStatusRequest = {
        brief: true,
        keyword: searchQuery.value || undefined,
        page: currentPage.value,
        page_size: pageSize.value,
      };
      const data = await vmmRpc.status(request);
      totalVMs.value = data.total || data.vms.length;
      hasMorePages.value = data.vms.length === pageSize.value && totalVMs.value > currentPage.value * pageSize.value;

      const previousVmMap = new Map<string, VmListItem>(vms.value.map((vmItem: VmListItem) => [vmItem.id, vmItem]));
      vms.value = (data.vms as VmListItem[]).map((vm) => {
        const previousVm = previousVmMap.get(vm.id);
        if (previousVm) {
          return {
            ...vm,
            configuration: previousVm.configuration,
            appCompose: previousVm.appCompose,
          };
        }
        return vm;
      });

      config.value = {
        ...config.value,
        portMappingEnabled: data.port_mapping_enabled,
      };

      if (expandedVMs.value.size > 0) {
        await refreshExpandedVMs();
      }
    } catch (error) {
      recordError('error loading vm list', error);
    }
  }

  async function refreshExpandedVMs() {
    try {
      for (const vmId of Array.from(expandedVMs.value.values()) as string[]) {
        await loadVMDetails(vmId);
      }
    } catch (error) {
      recordError('Error refreshing expanded VMs', error);
    }
  }

  async function loadVMDetails(vmId: string) {
    loadingVMDetails.value = true;
    try {
      const data = await vmmRpc.status({
        brief: false,
        ids: [vmId],
      });
      if (data.vms && data.vms.length > 0) {
        const detailedVM: any = data.vms[0];
        const appCompose = (() => {
          try {
            return JSON.parse(detailedVM.configuration?.compose_file || '{}');
          } catch (err) {
            console.error('Error parsing app config:', err);
            return {};
          }
        })();
        const index = vms.value.findIndex((vmItem) => vmItem.id === vmId);
        if (index !== -1) {
          vms.value[index] = { ...detailedVM, appCompose };
        }
      }
    } catch (error) {
      recordError(`Error loading details for VM ${vmId}`, error);
    } finally {
      loadingVMDetails.value = false;
    }
  }

  async function ensureVmDetails(vm: VmListItem): Promise<VmListItem | null> {
    if (vm.configuration?.compose_file && vm.appCompose) {
      return vm;
    }
    await loadVMDetails(vm.id);
    return vms.value.find((item) => item.id === vm.id) || null;
  }

  async function loadMeta() {
    try {
      const data = await vmmRpc.getMeta({});
      config.value = {
        ...config.value,
        networking: data.networking || null,
      };
    } catch (error) {
      recordError('error loading VMM metadata', error);
    }
  }

  async function loadImages() {
    try {
      const data = await vmmRpc.listImages({});
      availableImages.value = data.images || [];
    } catch (error) {
      recordError('error loading images', error);
    }
  }

  async function loadGpus() {
    try {
      const data = await vmmRpc.listGpus({});
      const gpus = data.gpus || [];
      availableGpus.value = gpus;
      availableGpuProducts.value = [];
      allowAttachAllGpus.value = data.allow_attach_all;
      for (const gpu of gpus) {
        if (!availableGpuProducts.value.find((product) => product.product_id === gpu.product_id)) {
          availableGpuProducts.value.push(gpu);
        }
      }
    } catch (error) {
      recordError('error loading GPUs', error);
    }
  }

  async function loadVersion() {
    const data = await vmmRpc.version({});
    version.value = data;
  }

  const imageVersion = (imageName: string) => {
    const image = availableImages.value.find((img) => img.name === imageName);
    return image?.version;
  };

  // Mirror of dstack-types::version::Version::parse. The prerelease/build
  // suffix is stripped at the first '-' or '+', then major.minor[.patch] are
  // read as decimal integers with patch defaulting to 0. So 0.6.1, 0.6.1-rc1,
  // 0.6.1.rc1 and 0.6.1+build.5 all parse to the same version: a release
  // candidate is built from the code of the version it is a candidate for and
  // must not be feature-gated down to the previous release.
  //
  // Returns null when the string is absent or not parseable; verGE then
  // reports false rather than silently comparing against NaN.
  const parseVer = (v: string | undefined): [number, number, number] | null => {
    if (!v) {
      return null;
    }
    // Deliberately not `Number()`: it accepts ' 6', '0x10' and '' where the
    // Rust parser rejects them, which would let the two sides disagree.
    const num = (s: string | undefined): number | null =>
      s !== undefined && /^\d+$/.test(s) ? Number(s) : null;
    const parts = v.trim().split(/[-+]/)[0].split('.');
    const major = num(parts[0]);
    const minor = num(parts[1]);
    const patch = parts.length > 2 ? num(parts[2]) : 0;
    if (major === null || minor === null || patch === null) {
      return null;
    }
    return [major, minor, patch];
  };

  const verGE = (versionStr: string | undefined, otherVersionStr: string) => {
    const version = parseVer(versionStr);
    const other = parseVer(otherVersionStr);
    if (!version || !other) {
      return false;
    }
    for (let i = 0; i < 3; i++) {
      if (version[i] !== other[i]) {
        return version[i] > other[i];
      }
    }
    return true;
  };

  const appComposeManifestVersion = (versionStr: string | undefined): number | string => {
    if (verGE(versionStr, '0.6.0')) {
      return '3';
    }
    return 2;
  };

  const imageVersionFeatures = (versionStr: string | undefined) => {
    const features = {
      progress: false,
      graceful_shutdown: false,
      network_info: false,
      compose_version: 1,
    };
    if (verGE(versionStr, '0.3.3')) {
      features.progress = true;
      features.graceful_shutdown = true;
      features.network_info = true;
      features.compose_version = 2;
    }
    if (verGE(versionStr, '0.4.2')) {
      features.compose_version = 3;
    }
    return features;
  };

  const imageFeatures = (vm: VmListItem) => imageVersionFeatures(vm.image_version);

  const vmStatus = (vm: VmListItem) => {
    const features = imageFeatures(vm);
    if (!features.progress) {
      return vm.status;
    }
    if (vm.status !== 'running') {
      return vm.status;
    }
    if (vm.shutdown_progress) {
      return 'shutting down';
    }
    if (vm.boot_progress === 'running') {
      return 'running';
    }
    if (vm.boot_progress !== 'done') {
      return 'booting';
    }
    return 'running';
  };

  const kmsEnabled = (vm: any) => getKeyProvider(vm) === 'kms';

  const gatewayEnabled = (vm: any) => vm.appCompose?.gateway_enabled;

  function formatMemory(memoryMB?: number) {
    if (!memoryMB) {
      return '0 MB';
    }
    if (memoryMB >= 1024) {
      const gbValue = (memoryMB / 1024).toFixed(1);
      return `${parseFloat(gbValue)} GB`;
    }
    return `${memoryMB} MB`;
  }

  async function calcComposeHash(appCompose: string) {
    const buffer = new TextEncoder().encode(appCompose);
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    return Array.from(new Uint8Array(hashBuffer))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  async function makeAppComposeFile() {
    const osVersion = imageVersion(vmForm.value.image);
    if (nonEmptyInitScripts(vmForm.value.initScripts).length > 1 && !verGE(osVersion, '0.6.0')) {
      throw new Error('Multiple init scripts require a dstack image version 0.6.0 or newer');
    }
    const appCompose: Record<string, unknown> = {
      manifest_version: appComposeManifestVersion(osVersion),
      name: vmForm.value.name,
      runner: 'docker-compose',
      docker_compose_file: vmForm.value.dockerComposeFile,
      gateway_enabled: vmForm.value.gateway_enabled,
      public_logs: vmForm.value.public_logs,
      public_sysinfo: vmForm.value.public_sysinfo,
      public_tcbinfo: vmForm.value.public_tcbinfo,
      key_provider_id: vmForm.value.key_provider === 'kms' || vmForm.value.key_provider === 'local'
        ? vmForm.value.key_provider_id
        : '',
      allowed_envs: vmForm.value.encryptedEnvs.map((env) => env.key),
      no_instance_id: !vmForm.value.gateway_enabled,
      secure_time: false,
    };

    if (vmForm.value.key_provider !== undefined) {
      appCompose.key_provider = vmForm.value.key_provider;

      // For backward compatibility
      if (vmForm.value.key_provider === 'kms') {
        appCompose.kms_enabled = true;
      }
      if (vmForm.value.key_provider === 'local') {
        appCompose.local_key_provider_enabled = true;
      }
    }

    if (vmForm.value.storage_fs) {
      appCompose.storage_fs = vmForm.value.storage_fs;
    }

    const initScripts = compatibleInitScripts(vmForm.value.initScripts);
    if (initScripts !== undefined) {
      appCompose.init_script = initScripts;
    }

    if (vmForm.value.preLaunchScript?.trim()) {
      appCompose.pre_launch_script = vmForm.value.preLaunchScript;
    }

    const swapBytes = Math.max(0, Math.round(vmForm.value.swap_size || 0));
    if (swapBytes > 0) {
      appCompose.swap_size = swapBytes;
    }

    if (vmForm.value.event_log_version && vmForm.value.event_log_version !== 1) {
      appCompose.event_log_version = vmForm.value.event_log_version;
    }

    const launchToken = vmForm.value.encryptedEnvs.find((env) => env.key === 'APP_LAUNCH_TOKEN');
    if (launchToken) {
      appCompose.launch_token_hash = await calcComposeHash(launchToken.value);
    }

    const imgFeatures = imageVersionFeatures(osVersion);
    if (imgFeatures.compose_version < 3) {
      appCompose.tproxy_enabled = appCompose.gateway_enabled;
      delete appCompose.gateway_enabled;
    }
    return JSON.stringify(appCompose);
  }

  async function makeUpdateComposeFile() {
    const currentAppCompose = updateDialog.value.vm.appCompose;
    const appCompose = {
      ...currentAppCompose,
      docker_compose_file: updateDialog.value.dockerComposeFile || currentAppCompose.docker_compose_file,
    };
    const targetManifestVersion = appComposeManifestVersion(imageVersion(updateDialog.value.image));
    if (nonEmptyInitScripts(updateDialog.value.initScripts).length > 1 && targetManifestVersion !== '3') {
      throw new Error('Multiple init scripts require a dstack image version 0.6.0 or newer');
    }
    if (targetManifestVersion === '3') {
      appCompose.manifest_version = targetManifestVersion;
    }
    if (updateDialog.value.resetSecrets) {
      // Update allowed_envs with the new environment variable keys
      appCompose.allowed_envs = updateDialog.value.encryptedEnvs.map(env => env.key);

      const launchToken = updateDialog.value.encryptedEnvs.find((env) => env.key === 'APP_LAUNCH_TOKEN');
      if (launchToken) {
        appCompose.launch_token_hash = await calcComposeHash(launchToken.value);
      }
    }
    appCompose.init_script = compatibleInitScripts(updateDialog.value.initScripts);
    appCompose.pre_launch_script = updateDialog.value.preLaunchScript?.trim() || undefined;

    const swapBytes = Math.max(0, Math.round(updateDialog.value.swap_size || 0));
    if (swapBytes > 0) {
      appCompose.swap_size = swapBytes;
    } else {
      delete appCompose.swap_size;
    }
    return JSON.stringify(appCompose);
  }

  watch(
    [
      () => vmForm.value.name,
      () => vmForm.value.dockerComposeFile,
      () => vmForm.value.preLaunchScript,
      () => vmForm.value.gateway_enabled,
      () => vmForm.value.public_logs,
      () => vmForm.value.public_sysinfo,
      () => vmForm.value.public_tcbinfo,
      () => vmForm.value.key_provider,
      () => vmForm.value.key_provider_id,
      () => vmForm.value.encryptedEnvs,
      () => vmForm.value.storage_fs,
    ],
    async () => {
      try {
        const appCompose = await makeAppComposeFile();
        composeHashPreview.value = await calcComposeHash(appCompose);
      } catch (error) {
        composeHashPreview.value = 'Error calculating hash';
        console.error('Failed to calculate compose hash', error);
      }
    },
    { deep: true },
  );

  watch(
    [
      () => updateDialog.value.dockerComposeFile,
      () => updateDialog.value.preLaunchScript,
      () => updateDialog.value.encryptedEnvs,
    ],
    async () => {
      if (!updateDialog.value.updateCompose) {
        updateComposeHashPreview.value = '';
        return;
      }
      try {
        const upgradedCompose = await makeUpdateComposeFile();
        updateComposeHashPreview.value = await calcComposeHash(upgradedCompose);
      } catch (error) {
        updateComposeHashPreview.value = 'Error calculating hash';
        console.error('Failed to calculate compose hash', error);
      }
    },
    { deep: true },
  );

  watch(pageSize, (newValue) => {
    localStorage.setItem('pageSize', String(newValue));
  });

  function showDeployDialog() {
    showCreateDialog.value = true;
    vmForm.value.encryptedEnvs = [];
    // A cancelled deploy and "Clone config" both leave their networking behind
    // in the shared form. Carrying it into the next deploy would silently pin
    // that VM's backend, bridge, macvtap parent and data plane to another VM's
    // -- invisibly, since the operator never opened the Networking section.
    vmForm.value.networks = [];
    vmForm.value.app_id = null;
    vmForm.value.swapValue = 0;
    vmForm.value.swapUnit = 'GB';
    vmForm.value.swap_size = 0;
    loadGpus();
  }

  async function showUpdateDialog(vm: VmListItem) {
    const detailedVm = await ensureVmDetails(vm);
    if (!detailedVm?.configuration?.compose_file || !detailedVm.appCompose) {
      alert('Compose file not available for this VM. Please expand its details first.');
      return;
    }
    const config = detailedVm.configuration;
    const memoryDisplay = autoMemoryDisplay(config.memory || 0);
    const swapDisplay = autoMemoryDisplay(bytesToMB(detailedVm.appCompose?.swap_size || 0));
    const gpuSelection = deriveGpuSelection(config.gpus);
    updateDialog.value = {
      show: true,
      vm: detailedVm,
      updateCompose: false,
      dockerComposeFile: detailedVm.appCompose.docker_compose_file || '',
      initScripts: initScriptList(detailedVm.appCompose.init_script),
      preLaunchScript: detailedVm.appCompose.pre_launch_script || '',
      encryptedEnvs: [],
      resetSecrets: false,
      vcpu: config.vcpu || 0,
      memory: config.memory || 0,
      memoryValue: memoryDisplay.memoryValue,
      memoryUnit: memoryDisplay.memoryUnit,
      swap_size: detailedVm.appCompose?.swap_size || 0,
      swapValue: swapDisplay.memoryValue,
      swapUnit: swapDisplay.memoryUnit,
      disk_size: config.disk_size || 0,
      image: config.image || '',
      ports: clonePortMappings(config.ports || []),
      // What the dialog opened with. `update_ports` means "this request moved
      // the port mappings", and the server refuses some mappings it has to
      // keep accepting on a request that only touched memory.
      originalPorts: normalizePorts(clonePortMappings(config.ports || [])),
      attachAllGpus: gpuSelection.attachAll,
      selectedGpus: gpuSelection.selected,
      updateGpuConfig: false,
      updateNetworking: false,
      networks: cloneNetworks(config),
      user_config: config.user_config || '',
    };
  }

  function parseEnvFile(content: string) {
    const lines = content
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith('#'));
    const envs: Record<string, string> = {};
    for (const line of lines) {
      const [key, ...parts] = line.split('=');
      if (!key || parts.length === 0) {
        continue;
      }
      envs[key.trim()] = parts.join('=').trim();
    }
    return envs;
  }

  async function calcAppId(compose: string) {
    const composeHash = await calcComposeHash(compose);
    return composeHash.slice(0, 40);
  }

  async function encryptEnv(envs: EncryptedEnvEntry[], kmsEnabled: boolean, appId: string | null) {
    if (!kmsEnabled || envs.length === 0) {
      return undefined;
    }
    let appIdToUse = appId;
    if (!appIdToUse) {
      const appCompose = await makeAppComposeFile();
      appIdToUse = await calcAppId(appCompose);
    }
    const keyBytes = hexToBytes(appIdToUse);
    const response = await vmmRpc.getAppEnvEncryptPubKey({ app_id: keyBytes });
    return encryptEnvWithKey(envs, response.public_key);
  }

  async function encryptEnvWithKey(envs: EncryptedEnvEntry[], publicKeyBytes: Uint8Array) {
    const envsJson = JSON.stringify({ env: envs });
    const remotePubkey = publicKeyBytes && publicKeyBytes.length ? publicKeyBytes : new Uint8Array();

    const seed = crypto.getRandomValues(new Uint8Array(32));
    const keyPair = x25519.generateKeyPair(seed);
    const shared = x25519.sharedKey(keyPair.private, remotePubkey);

    const importedShared = await crypto.subtle.importKey(
      'raw',
      shared,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt'],
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      importedShared,
      new TextEncoder().encode(envsJson),
    );

    const result = new Uint8Array(iv.length + keyPair.public.byteLength + encrypted.byteLength);
    result.set(keyPair.public, 0);
    result.set(iv, keyPair.public.byteLength);
    result.set(new Uint8Array(encrypted), keyPair.public.byteLength + iv.length);

    return result;
  }

  async function createVm() {
    try {
      vmForm.value.memory = convertMemoryToMB(vmForm.value.memoryValue, vmForm.value.memoryUnit);
      const composeFile = await makeAppComposeFile();
      const encryptedEnv = await encryptEnv(
        vmForm.value.encryptedEnvs,
        vmForm.value.key_provider === 'kms',
        vmForm.value.app_id,
      );
      const payload = buildCreateVmPayload({
        name: vmForm.value.name,
        image: vmForm.value.image,
        compose_file: composeFile,
        vcpu: vmForm.value.vcpu,
        memory: vmForm.value.memory,
        disk_size: vmForm.value.disk_size,
        ports: vmForm.value.ports,
        encrypted_env: encryptedEnv || undefined,
        app_id: vmForm.value.app_id || undefined,
        user_config: vmForm.value.user_config,
        hugepages: vmForm.value.hugepages,
        pin_numa: vmForm.value.pin_numa,
        no_tee: vmForm.value.no_tee,
        simulated_tee: vmForm.value.simulated_tee,
        networks: vmForm.value.networks,
        gpus: configGpu(vmForm.value) || undefined,
        kms_urls: vmForm.value.kms_urls,
        gateway_urls: vmForm.value.gateway_urls,
        stopped: vmForm.value.stopped,
      });

      await vmmRpc.createVm(payload);
      leaveCreateDialog();
      loadVMList();
    } catch (error) {
      recordError('Error creating VM', error);
      alert(error instanceof Error ? error.message : 'Failed to create VM');
    }
  }

  function leaveCreateDialog() {
    showCreateDialog.value = false;
  }

  function loadComposeFile(event: Event) {
    const input = event.target as HTMLInputElement | null;
    const file = input?.files?.[0];
    if (!file) {
      return;
    }
    const reader = new FileReader();
    reader.onload = (e: any) => {
      vmForm.value.dockerComposeFile = e.target.result;
    };
    reader.readAsText(file);
    if (input) {
      input.value = '';
    }
  }

  function loadUpdateFile(event: Event) {
    const input = event.target as HTMLInputElement | null;
    const file = input?.files?.[0];
    if (!file) {
      return;
    }
    const reader = new FileReader();
    reader.onload = (e: any) => {
      updateDialog.value.dockerComposeFile = e.target.result;
    };
    reader.readAsText(file);
    if (input) {
      input.value = '';
    }
  }

  async function updateVM() {
    try {
      const vm = updateDialog.value.vm;
      const original = vm.configuration;
      const updated = updateDialog.value;

      const body: VmmTypes.IUpdateVmRequest = {
        id: vm.id,
      };

      const fieldsToCompare = ['vcpu', 'memory', 'disk_size', 'image'];
      if (fieldsToCompare.some((field) => updated[field] !== original[field])) {
        body.vcpu = updated.vcpu;
        body.memory = updated.memory;
        body.disk_size = updated.disk_size;
        body.image = updated.image;
      }

      const composeWasExplicitlyUpdated = updateDialog.value.updateCompose;
      let composeNeedsUpdate = composeWasExplicitlyUpdated;
      let encryptedEnvPayload;
      if (updateDialog.value.resetSecrets) {
        const keyResponse = await vmmRpc.getAppEnvEncryptPubKey({ app_id: hexToBytes(vm.app_id || '') });
        encryptedEnvPayload = await encryptEnvWithKey(updateDialog.value.encryptedEnvs, keyResponse.public_key);
        composeNeedsUpdate = true;
      }
      body.compose_file = composeNeedsUpdate ? await makeUpdateComposeFile() : undefined;
      body.encrypted_env = encryptedEnvPayload;
      body.user_config = updated.user_config;
      const ports = normalizePorts(updated.ports);
      const portsMoved =
        JSON.stringify(ports) !== JSON.stringify(updateDialog.value.originalPorts ?? []);
      if (portsMoved) {
        body.update_ports = true;
        body.ports = ports;
      }
      body.gpus = updateDialog.value.updateGpuConfig ? configGpu(updated, true) : undefined;
      if (updated.updateNetworking) {
        body.update_networking = true;
        body.networks = normalizeNetworks(updated.networks);
      }

      await vmmRpc.updateVm(body);
      updateDialog.value.encryptedEnvs = [];
      updateDialog.value.show = false;
      if (composeWasExplicitlyUpdated) {
        updateMessage.value = '✅ Compose file updated!';
      }
      loadVMList();
    } catch (error) {
      recordError('error upgrading VM', error);
      alert(error instanceof Error ? error.message : 'Failed to upgrade VM');
    }
  }

  function getKeyProvider(vm: VmListItem): KeyProviderKind {
    if (vm.appCompose?.key_provider) {
      return vm.appCompose?.key_provider;
    }
    if (vm.appCompose?.kms_enabled) {
      return 'kms';
    }
    if (vm.appCompose?.local_key_provider_enabled) {
      return 'local';
    }
    return 'none';
  }

  async function showCloneConfig(vm: VmListItem) {
    const theVm = await ensureVmDetails(vm);
    if (!theVm?.configuration?.compose_file) {
      alert('Compose file not available for this VM. Please open its details first.');
      return;
    }
    const config = theVm.configuration;

    // Populate vmForm with current VM data, but clear envs and ports
    vmForm.value = {
      name: `${config.name || vm.name}`,
      image: config.image || '',
      dockerComposeFile: theVm.appCompose?.docker_compose_file || '',
      initScripts: initScriptList(theVm.appCompose?.init_script),
      preLaunchScript: theVm.appCompose?.pre_launch_script || '',
      vcpu: config.vcpu || 1,
      memory: config.memory || 0,
      memoryValue: autoMemoryDisplay(config.memory || 0).memoryValue,
      memoryUnit: autoMemoryDisplay(config.memory || 0).memoryUnit,
      swap_size: theVm.appCompose?.swap_size || 0,
      swapValue: autoMemoryDisplay(bytesToMB(theVm.appCompose?.swap_size || 0)).memoryValue,
      swapUnit: autoMemoryDisplay(bytesToMB(theVm.appCompose?.swap_size || 0)).memoryUnit,
      disk_size: config.disk_size || 0,
      selectedGpus: [],
      attachAllGpus: false,
      encryptedEnvs: [], // Clear environment variables
      ports: [], // Clear port mappings
      storage_fs: theVm.appCompose?.storage_fs || 'zfs',
      app_id: config.app_id || '',
      kms_urls: config.kms_urls || [],
      key_provider: getKeyProvider(theVm),
      key_provider_id: theVm.appCompose?.key_provider_id || '',
      gateway_enabled: !!theVm.appCompose?.gateway_enabled,
      gateway_urls: config.gateway_urls || [],
      networks: cloneNetworks(config),
      public_logs: !!theVm.appCompose?.public_logs,
      public_sysinfo: !!theVm.appCompose?.public_sysinfo,
      public_tcbinfo: !!theVm.appCompose?.public_tcbinfo,
      pin_numa: !!config.pin_numa,
      hugepages: !!config.hugepages,
      no_tee: !!config.no_tee,
      simulated_tee: config.simulated_tee || '',
      user_config: config.user_config || '',
      stopped: !!config.stopped,
      event_log_version: theVm.appCompose?.event_log_version || 1,
    };

    // Show Create VM dialog instead of Clone Config dialog
    showCreateDialog.value = true;
  }

  async function cloneConfig() {
    try {
      const source = cloneConfigDialog.value;
      if (!source.compose_file) {
        alert('Compose file not available for this VM. Please open its details first.');
        return;
      }
      const payload = buildCreateVmPayload({
        name: source.name,
        image: source.image,
        compose_file: source.compose_file,
        vcpu: source.vcpu,
        memory: source.memory,
        disk_size: source.disk_size,
        ports: source.ports,
        encrypted_env: source.encrypted_env,
        app_id: source.app_id,
        user_config: source.user_config,
        hugepages: source.hugepages,
        pin_numa: source.pin_numa,
        no_tee: source.no_tee,
        simulated_tee: source.simulated_tee,
        networks: source.networks,
        gpus: source.gpus,
        kms_urls: source.kms_urls,
        gateway_urls: source.gateway_urls,
        stopped: source.stopped,
      });
      await vmmRpc.createVm(payload);
      cloneConfigDialog.value.show = false;
      loadVMList();
    } catch (error) {
      recordError('Error creating VM', error);
      alert('Failed to create VM');
    }
  }

  function toggleDetails(vm: VmListItem) {
    if (expandedVMs.value.has(vm.id)) {
      expandedVMs.value.delete(vm.id);
    } else {
      // Close all other expanded VMs
      expandedVMs.value.clear();
      expandedVMs.value.add(vm.id);
      loadVMDetails(vm.id);
      refreshNetworkInfo(vm);
    }
  }

  async function refreshNetworkInfo(vm: VmListItem) {
    if (vm.status !== 'running' || !imageFeatures(vm).network_info) {
      return;
    }
    const response = await guestRpcCall('NetworkInfo', { id: vm.id });
    const data = await response.json();
    networkInfo.value[vm.id] = data;
  }

  function nextPage() {
    if (hasMorePages.value) {
      currentPage.value += 1;
      pageInput.value = currentPage.value;
      loadVMList();
    }
  }

  function prevPage() {
    if (currentPage.value > 1) {
      currentPage.value -= 1;
      pageInput.value = currentPage.value;
      loadVMList();
    }
  }

  function goToPage() {
    let page = Number.parseInt(String(pageInput.value), 10);
    if (Number.isNaN(page) || page < 1) {
      page = 1;
    } else if (page > maxPage.value) {
      page = maxPage.value;
    }
    pageInput.value = page;
    currentPage.value = page;
    loadVMList();
  }

  function closeAllDropdowns() {
    document.querySelectorAll('.dropdown-content').forEach((dropdown) => dropdown.classList.remove('show'));
    systemMenu.value.show = false;
    document.removeEventListener('click', closeAllDropdowns);
  }

  function toggleSystemMenu(event: Event) {
    event.stopPropagation();
    systemMenu.value.show = !systemMenu.value.show;

    // Close all other dropdowns
    document.querySelectorAll('.dropdown-content').forEach((dropdown) => {
      dropdown.classList.remove('show');
    });

    if (systemMenu.value.show) {
      document.addEventListener('click', closeAllDropdowns);
    } else {
      document.removeEventListener('click', closeAllDropdowns);
    }
  }

  function closeSystemMenu() {
    systemMenu.value.show = false;
  }

  function openApiDocs() {
    closeSystemMenu();
    window.open('/api-docs/docs', '_blank', 'noopener');
  }

  function shortUptime(uptime?: string | null) {
    if (!uptime) {
      return '-';
    }
    const parts = uptime.split(/\s+/).filter(Boolean);
    if (parts.length === 0) {
      return uptime;
    }
    return parts.slice(0, Math.min(2, parts.length)).join(' ');
  }
  function toggleDevMode() {
    devMode.value = !devMode.value;
    localStorage.setItem('devMode', devMode.value ? 'true' : 'false');
    closeSystemMenu();
    successMessage.value = devMode.value ? '✅ Dev mode enabled' : 'Dev mode disabled';
    setTimeout(() => {
      successMessage.value = '';
    }, 2000);
  }

  async function reloadVMs() {
    try {
      errorMessage.value = '';
      successMessage.value = '';

      const response = await vmmRpc.reloadVms({});

      // Show success message with statistics
      if (response.loaded > 0 || response.updated > 0 || response.removed > 0) {
        let message = 'VM reload completed: ';
        const parts = [];
        if (response.loaded > 0) parts.push(`${response.loaded} loaded`);
        if (response.updated > 0) parts.push(`${response.updated} updated`);
        if (response.removed > 0) parts.push(`${response.removed} removed`);

        successMessage.value = message + parts.join(', ');
      } else {
        successMessage.value = 'VM reload completed: no changes detected';
      }

      // Reload the VM list to show updated data
      await loadVMList();

      // Hide message after 5 seconds
      setTimeout(() => {
        successMessage.value = '';
      }, 5000);

    } catch (error: any) {
      console.error('Failed to reload VMs:', error);
      errorMessage.value = `Failed to reload VMs: ${error.message || error.toString()}`;

      // Hide error message after 10 seconds
      setTimeout(() => {
        errorMessage.value = '';
      }, 10000);
    }
  }

  function toggleDropdown(event: Event, vm: VmListItem) {
    document.querySelectorAll('.dropdown-content').forEach((dropdown) => {
      if (dropdown.id !== `dropdown-${vm.id}`) {
        dropdown.classList.remove('show');
      }
    });
    const dropdownContent = document.getElementById(`dropdown-${vm.id}`);
    dropdownContent?.classList.toggle('show');

    event.stopPropagation();

    document.addEventListener('click', closeAllDropdowns);
  }

  function onPageSizeChange() {
    currentPage.value = 1;
    pageInput.value = 1;
    loadVMList();
  }

  async function startVm(id: string) {
    try {
      await vmmRpc.startVm({ id });
      loadVMList();
    } catch (error) {
      recordError('Failed to start VM', error);
    }
  }

  async function shutdownVm(id: string) {
    try {
      await vmmRpc.shutdownVm({ id });
      loadVMList();
    } catch (error) {
      recordError('Failed to shutdown VM', error);
    }
  }

  const dangerConfirmEnabled = () => !devMode.value;

  async function stopVm(vm: VmListItem) {
    if (dangerConfirmEnabled() &&
        !confirm(`You are killing "${vm.name}". This might cause data corruption.`)) {
      return;
    }
    try {
      await vmmRpc.stopVm({ id: vm.id });
      loadVMList();
    } catch (error) {
      recordError(`Failed to stop ${vm.name}`, error);
    }
  }

  async function removeVm(vm: VmListItem) {
    if (dangerConfirmEnabled() &&
        !confirm('Remove VM? This action cannot be undone.')) {
      return;
    }

    try {
      if (devMode.value && vm.status === 'running') {
        try {
          await vmmRpc.stopVm({ id: vm.id });
        } catch (error) {
          recordError(`Failed to stop ${vm.name} before removal`, error);
          return;
        }
      }

      await vmmRpc.removeVm({ id: vm.id });
      loadVMList();
    } catch (error) {
      recordError(`Failed to remove ${vm.name}`, error);
    }
  }

  function showLogs(id: string, channel: string) {
    window.open(`/logs?id=${encodeURIComponent(id)}&follow=true&ansi=false&lines=200&ch=${channel}`, '_blank');
  }

  function showDashboard(vm: VmListItem) {
    if (vm.app_url) {
      window.open(vm.app_url, '_blank');
    } else {
      alert('No guest agent dashboard URL');
    }
  }

  async function watchVmList() {
    while (true) {
      try {
        await loadVMList();
      } catch (error) {
        recordError('error loading VM list', error);
      }
      await new Promise((resolve) => setTimeout(resolve, 3000));
    }
  }

  async function copyToClipboard(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      successMessage.value = '✅ Copied to clipboard!';
      setTimeout(() => {
        successMessage.value = '';
      }, 2000);
    } catch (error) {
      console.error('Failed to copy to clipboard', error);
      errorMessage.value = 'Failed to copy to clipboard';
      setTimeout(() => {
        errorMessage.value = '';
      }, 3000);
    }
  }

  function downloadFile(filename: string, content: string) {
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  function downloadAppCompose(vm: VmListItem) {
    if (vm.configuration?.compose_file) {
      downloadFile(`${vm.name}-app-compose.json`, vm.configuration.compose_file);
    }
  }

  function downloadUserConfig(vm: VmListItem) {
    if (vm.configuration?.user_config) {
      downloadFile(`${vm.name}-user-config.txt`, vm.configuration.user_config);
    }
  }

  function getVmFeatures(vm: VmListItem) {
    const features = [];

    const kp = getKeyProvider(vm);
    if (kp && kp != 'none') features.push(kp);

    // Check Gateway/TProxy
    if (vm.appCompose?.gateway_enabled) features.push("gateway");

    // Check other features from appCompose
    if (vm.appCompose?.public_logs) features.push("logs");
    if (vm.appCompose?.public_sysinfo) features.push("sysinfo");
    if (vm.appCompose?.public_tcbinfo) features.push("tcbinfo");

    return features.length > 0 ? features.join(', ') : 'None';
  }

  // ── Image Registry ─────────────────────────────────────────────
  const showImageRegistry = ref(false);
  const registryImages = ref([] as Array<{ tag: string; local: boolean; pulling: boolean; error: string }>);
  const registryLoading = ref(false);
  let registryRefreshTimer: ReturnType<typeof setInterval> | null = null;

  async function loadRegistryImages() {
    const isInitialLoad = registryImages.value.length === 0;
    if (isInitialLoad) {
      registryLoading.value = true;
    }
    try {
      const data = await vmmRpc.listRegistryImages({});
      registryImages.value = (data.images || []).sort((a: any, b: any) => {
        // Sort by tag descending (newest versions first)
        return (b.tag || '').localeCompare(a.tag || '', undefined, { numeric: true });
      });
      // If any image is pulling, refresh local images too
      if (registryImages.value.some((img: any) => img.pulling)) {
        loadImages();
      }
    } catch (error) {
      recordError('failed to load registry images', error);
    } finally {
      registryLoading.value = false;
    }
  }

  async function pullRegistryImage(tag: string) {
    // Optimistic update: mark as pulling immediately, clear previous error
    const img = registryImages.value.find((i: any) => i.tag === tag);
    if (img) {
      img.pulling = true;
      img.error = '';
    }
    try {
      await vmmRpc.pullRegistryImage({ tag });
    } catch (error) {
      // Revert optimistic update on failure
      if (img) {
        img.pulling = false;
      }
      recordError(`failed to pull image ${tag}`, error);
    }
  }

  async function deleteImage(name: string) {
    if (!confirm(`Delete local image "${name}"?`)) return;
    try {
      await vmmRpc.deleteImage({ id: name });
      await loadImages();
      await loadRegistryImages();
    } catch (error) {
      recordError(`failed to delete image ${name}`, error);
    }
  }

  async function openImageRegistry() {
    showImageRegistry.value = true;
    await Promise.all([loadImages(), loadRegistryImages()]);
    registryRefreshTimer = setInterval(async () => {
      await loadRegistryImages();
      // Refresh local images if something just finished pulling
      if (registryImages.value.some((img: any) => img.pulling)) {
        await loadImages();
      }
    }, 3000);
  }

  watch(showImageRegistry, (open) => {
    if (!open && registryRefreshTimer) {
      clearInterval(registryRefreshTimer);
      registryRefreshTimer = null;
    }
  });

  // ── Process Manager ─────────────────────────────────────────────
  const showProcessManager = ref(false);
  const supervisorProcesses = ref([] as any[]);

  function svStatusClass(p: any): string {
    const s = p.status || '';
    if (s === 'running') return 'sv-status-running';
    if (s === 'stopped') return 'sv-status-stopped';
    if (s.startsWith('exited')) return 'sv-status-exited';
    return 'sv-status-error';
  }

  function svIsRunning(p: any): boolean {
    return p.status === 'running';
  }

  function svIsStopped(p: any): boolean {
    return p.status !== 'running';
  }

  async function loadSupervisorProcesses() {
    try {
      const resp = await baseRpcCall('/prpc/SvList');
      const json = await resp.json();
      supervisorProcesses.value = json.processes || [];
    } catch (error) {
      recordError('Failed to load processes', error);
    }
  }

  let svRefreshTimer: ReturnType<typeof setInterval> | null = null;

  async function openProcessManager() {
    showProcessManager.value = true;
    await loadSupervisorProcesses();
    svRefreshTimer = setInterval(loadSupervisorProcesses, 3000);
  }

  watch(showProcessManager, (open) => {
    if (!open && svRefreshTimer) {
      clearInterval(svRefreshTimer);
      svRefreshTimer = null;
    }
  });

  async function svStop(id: string) {
    try {
      await baseRpcCall('/prpc/SvStop', { id });
      await new Promise(r => setTimeout(r, 500));
      await loadSupervisorProcesses();
    } catch (error) {
      recordError('Failed to stop process', error);
    }
  }

  async function svRemove(id: string) {
    try {
      await baseRpcCall('/prpc/SvRemove', { id });
      await loadSupervisorProcesses();
    } catch (error) {
      recordError('Failed to remove process', error);
    }
  }

  async function svClear() {
    try {
      const stopped = supervisorProcesses.value.filter(p => svIsStopped(p));
      for (const p of stopped) {
        await baseRpcCall('/prpc/SvRemove', { id: p.id });
      }
      await loadSupervisorProcesses();
    } catch (error) {
      recordError('Failed to clear stopped processes', error);
    }
  }

  onMounted(() => {
    watchVmList();
    loadMeta();
    loadImages();
    loadGpus();
    loadVersion();
  });

  return {
    version,
    vms,
    expandedVMs,
    networkInfo,
    searchQuery,
    currentPage,
    pageInput,
    pageSize,
    totalVMs,
    hasMorePages,
    loadingVMDetails,
    maxPage,
    vmForm,
    availableImages,
    availableGpus,
    availableGpuProducts,
    allowAttachAllGpus,
    updateDialog,
    updateMessage,
    successMessage,
    errorMessage,
    cloneConfigDialog,
    showCreateDialog,
    config,
    networkingModes,
    defaultBridge,
    maxNetQueues,
    defaultNetworkingLabel,
    defaultModeTunable,
    defaultVhostOn,
    composeHashPreview,
    updateComposeHashPreview,
    showDeployDialog,
    leaveCreateDialog,
    loadComposeFile,
    loadUpdateFile,
    createVm,
    updateVM,
    cloneConfig,
    loadVMList,
    toggleDetails,
    toggleDropdown,
    closeAllDropdowns,
    showLogs,
    showDashboard,
    stopVm,
    shutdownVm,
    startVm,
    removeVm,
    showUpdateDialog,
    showCloneConfig,
    formatMemory,
    bytesToMB,
    vmStatus,
    kmsEnabled,
    gatewayEnabled,
    goToPage,
    nextPage,
    prevPage,
    onPageSizeChange,
    copyToClipboard,
    downloadAppCompose,
    downloadUserConfig,
    getVmFeatures,
    networkModeLabel,
    systemMenu,
    toggleSystemMenu,
    closeSystemMenu,
    openApiDocs,
    reloadVMs,
    devMode,
    toggleDevMode,
    shortUptime,
    showProcessManager,
    supervisorProcesses,
    openProcessManager,
    loadSupervisorProcesses,
    svStop,
    svRemove,
    svClear,
    svStatusClass,
    svIsRunning,
    svIsStopped,
    showImageRegistry,
    registryImages,
    registryLoading,
    loadRegistryImages,
    pullRegistryImage,
    deleteImage,
    openImageRegistry,
  };
}

export { useVmManager };
