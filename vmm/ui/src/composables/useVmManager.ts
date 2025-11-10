// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
// SPDX-License-Identifier: Apache-2.0

declare const Vue: any;
const { ref, computed, watch, onMounted } = Vue;
import type { vmm as VmmTypes } from '../proto/vmm_rpc';

// Types based on Rust definitions
type VmConfiguration = VmmTypes.IVmConfiguration;

type AppCompose = {
  manifest_version: number;
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
  storage_fs?: string;
  swap_size: number;
  launch_token_hash?: string;
  pre_launch_script?: string;
};

type KeyProviderKind = 'none' | 'kms' | 'local';

const x25519 = require('../lib/x25519.js');
const { getVmmRpcClient } = require('../lib/vmmRpcClient');

const vmmRpc = getVmmRpcClient();

// Initialize dangerConfirm setting
if (localStorage.getItem('dangerConfirm') === null) {
  localStorage.setItem('dangerConfirm', 'true');
}

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
};

type VmFormState = {
  name: string;
  image: string;
  dockerComposeFile: string;
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
  kms_enabled: boolean;
  local_key_provider_enabled: boolean;
  key_provider_id: string;
  gateway_enabled: boolean;
  public_logs: boolean;
  public_sysinfo: boolean;
  public_tcbinfo: boolean;
  pin_numa: boolean;
  hugepages: boolean;
  user_config: string;
  kms_urls: string[];
  gateway_urls: string[];
  stopped: boolean;
};

type UpdateDialogState = {
  show: boolean;
  vm: VmListItem | null;
  updateCompose: boolean;
  dockerComposeFile: string;
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
  attachAllGpus: boolean;
  selectedGpus: string[];
  updateGpuConfig: boolean;
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
  hugepages: boolean;
  pin_numa: boolean;
  encrypted_env?: Uint8Array;
  app_id?: string;
  stopped: boolean;
};

function createVmFormState(preLaunchScript: string): VmFormState {
  return {
    name: '',
    image: '',
    dockerComposeFile: '',
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
    kms_enabled: true,
    local_key_provider_enabled: false,
    key_provider_id: '',
    gateway_enabled: true,
    public_logs: true,
    public_sysinfo: true,
    public_tcbinfo: true,
    pin_numa: false,
    hugepages: false,
    user_config: '',
    kms_urls: [],
    gateway_urls: [],
    stopped: false,
  };
}

function createUpdateDialogState(): UpdateDialogState {
  return {
    show: false,
    vm: null,
    updateCompose: false,
    dockerComposeFile: '',
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
    attachAllGpus: false,
    selectedGpus: [],
    updateGpuConfig: false,
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
    hugepages: false,
    pin_numa: false,
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
  const config = ref({ portMappingEnabled: false });
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
    }));

  const normalizePorts = (ports: PortFormEntry[] = []): VmmTypes.IPortMapping[] =>
    ports
      .map((port) => {
        const protocol = (port.protocol || '').trim();
        const hostPort =
          port.host_port === null || port.host_port === undefined ? Number.NaN : Number(port.host_port);
        const vmPort =
          port.vm_port === null || port.vm_port === undefined ? Number.NaN : Number(port.vm_port);
        return {
          protocol,
          host_address: (port.host_address || '127.0.0.1').trim() || '127.0.0.1',
          host_port: hostPort,
          vm_port: vmPort,
        };
      })
      .filter(
        (port) =>
          port.protocol.length > 0 &&
          Number.isFinite(port.host_port) &&
          Number.isFinite(port.vm_port),
      )
      .map((port) => ({
        protocol: port.protocol,
        host_address: port.host_address,
        host_port: port.host_port,
        vm_port: port.vm_port,
      }));

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

  function configGpu(form: { attachAllGpus: boolean; selectedGpus: string[] }): VmmTypes.IGpuConfig | undefined {
    if (form.attachAllGpus) {
      return { attach_mode: 'all' };
    }
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
    gpus?: VmmTypes.IGpuConfig;
    kms_urls?: string[];
    gateway_urls?: string[];
    stopped?: boolean;
  };

  function buildCreateVmPayload(source: CreateVmPayloadSource): VmmTypes.IVmConfiguration {
    const normalizedPorts = normalizePorts(source.ports);
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

      config.value = { portMappingEnabled: data.port_mapping_enabled };

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

  const verGE = (versionStr: string, otherVersionStr: string) => {
    const versionParts = versionStr.split('.').map(Number);
    const otherParts = otherVersionStr.split('.').map(Number);
    return (
      versionParts[0] > otherParts[0] ||
      (versionParts[0] === otherParts[0] && versionParts[1] > otherParts[1]) ||
      (versionParts[0] === otherParts[0] && versionParts[1] === otherParts[1] && versionParts[2] >= otherParts[2])
    );
  };

  const imageVersionFeatures = (versionStr: string | undefined) => {
    const features = {
      progress: false,
      graceful_shutdown: false,
      network_info: false,
      compose_version: 1,
    };
    if (!versionStr) {
      return features;
    }
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

  const kmsEnabled = (vm: any) => vm.appCompose?.kms_enabled || vm.appCompose?.features?.includes('kms');

  const gatewayEnabled = (vm: any) =>
    vm.appCompose?.gateway_enabled || vm.appCompose?.tproxy_enabled || vm.appCompose?.features?.includes('tproxy-net');

  const defaultTrue = (v: boolean | undefined) => (v === undefined ? true : v);

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
    const appCompose: Record<string, unknown> = {
      manifest_version: 2,
      name: vmForm.value.name,
      runner: 'docker-compose',
      docker_compose_file: vmForm.value.dockerComposeFile,
      kms_enabled: vmForm.value.kms_enabled,
      gateway_enabled: vmForm.value.gateway_enabled,
      public_logs: vmForm.value.public_logs,
      public_sysinfo: vmForm.value.public_sysinfo,
      public_tcbinfo: vmForm.value.public_tcbinfo,
      local_key_provider_enabled: vmForm.value.local_key_provider_enabled,
      key_provider_id: vmForm.value.key_provider_id,
      allowed_envs: vmForm.value.encryptedEnvs.map((env) => env.key),
      no_instance_id: !vmForm.value.gateway_enabled,
      secure_time: false,
    };

    if (vmForm.value.storage_fs) {
      appCompose.storage_fs = vmForm.value.storage_fs;
    }

    if (vmForm.value.preLaunchScript?.trim()) {
      appCompose.pre_launch_script = vmForm.value.preLaunchScript;
    }

    const swapBytes = Math.max(0, Math.round(vmForm.value.swap_size || 0));
    if (swapBytes > 0) {
      appCompose.swap_size = swapBytes;
    }

    const launchToken = vmForm.value.encryptedEnvs.find((env) => env.key === 'APP_LAUNCH_TOKEN');
    if (launchToken) {
      appCompose.launch_token_hash = await calcComposeHash(launchToken.value);
    }

    const imgFeatures = imageVersionFeatures(imageVersion(vmForm.value.image));
    if (imgFeatures.compose_version < 2) {
      const features: string[] = [];
      if (vmForm.value.kms_enabled) features.push('kms');
      if (vmForm.value.gateway_enabled) features.push('tproxy-net');
      appCompose.features = features;
      appCompose.manifest_version = 1;
      appCompose.version = '1.0.0';
    }
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
    if (updateDialog.value.resetSecrets) {
      // Update allowed_envs with the new environment variable keys
      appCompose.allowed_envs = updateDialog.value.encryptedEnvs.map(env => env.key);

      const launchToken = updateDialog.value.encryptedEnvs.find((env) => env.key === 'APP_LAUNCH_TOKEN');
      if (launchToken) {
        appCompose.launch_token_hash = await calcComposeHash(launchToken.value);
      }
    }
    appCompose.pre_launch_script = updateDialog.value.preLaunchScript?.trim();

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
      () => vmForm.value.kms_enabled,
      () => vmForm.value.gateway_enabled,
      () => vmForm.value.public_logs,
      () => vmForm.value.public_sysinfo,
      () => vmForm.value.public_tcbinfo,
      () => vmForm.value.local_key_provider_enabled,
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
      attachAllGpus: gpuSelection.attachAll,
      selectedGpus: gpuSelection.selected,
      updateGpuConfig: false,
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
        vmForm.value.kms_enabled,
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
      alert('Failed to create VM');
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

      const fieldsToCompare = ['vcpu', 'memory', 'disk_size', 'image'];
      if (fieldsToCompare.some((field) => updated[field] !== original[field])) {
        const resizePayload: VmmTypes.IResizeVmRequest = {
          id: vm.id,
          vcpu: updated.vcpu,
          memory: updated.memory,
          disk_size: updated.disk_size,
          image: updated.image,
        };
        await vmmRpc.resizeVm(resizePayload);
      }

      const composeWasExplicitlyUpdated = updateDialog.value.updateCompose;
      let composeNeedsUpdate = composeWasExplicitlyUpdated;
      let encryptedEnvPayload;
      if (updateDialog.value.resetSecrets) {
        const keyResponse = await vmmRpc.getAppEnvEncryptPubKey({ app_id: hexToBytes(vm.app_id || '') });
        encryptedEnvPayload = await encryptEnvWithKey(updateDialog.value.encryptedEnvs, keyResponse.public_key);
        composeNeedsUpdate = true;
      }
      const body: VmmTypes.IUpgradeAppRequest = {
        id: vm.id,
        compose_file: composeNeedsUpdate ? await makeUpdateComposeFile() : undefined,
        encrypted_env: encryptedEnvPayload,
        user_config: updated.user_config,
        update_ports: true,
        ports: normalizePorts(updated.ports),
        gpus: updateDialog.value.updateGpuConfig ? configGpu(updated) : undefined,
      };

      await vmmRpc.upgradeApp(body);
      updateDialog.value.encryptedEnvs = [];
      updateDialog.value.show = false;
      if (composeWasExplicitlyUpdated) {
        updateMessage.value = '✅ Compose file updated!';
      }
      loadVMList();
    } catch (error) {
      recordError('error upgrading VM', error);
      alert('failed to upgrade VM');
    }
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
      name: `${config.name || vm.name}-cloned`,
      image: config.image || '',
      dockerComposeFile: theVm.appCompose?.docker_compose_file || '',
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
      storage_fs: theVm.appCompose?.storage_fs || 'ext4',
      app_id: config.app_id || '',
      kms_enabled: !!theVm.appCompose?.kms_enabled,
      kms_urls: config.kms_urls || [],
      local_key_provider_enabled: !!theVm.appCompose?.local_key_provider_enabled,
      key_provider_id: theVm.appCompose?.key_provider_id || '',
      gateway_enabled: !!theVm.appCompose?.gateway_enabled,
      gateway_urls: config.gateway_urls || [],
      public_logs: !!theVm.appCompose?.public_logs,
      public_sysinfo: !!theVm.appCompose?.public_sysinfo,
      public_tcbinfo: !!theVm.appCompose?.public_tcbinfo,
      pin_numa: !!config.pin_numa,
      hugepages: !!config.hugepages,
      user_config: config.user_config || '',
      stopped: !!config.stopped,
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
    document.removeEventListener('click', closeAllDropdowns);
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
    await vmmRpc.startVm({ id });
    loadVMList();
  }

  async function shutdownVm(id: string) {
    await vmmRpc.shutdownVm({ id });
    loadVMList();
  }

  async function stopVm(vm: VmListItem) {
    if (localStorage.getItem('dangerConfirm') === 'true' &&
        !confirm(`You are killing "${vm.name}". This might cause data corruption.`)) {
      return;
    }
    await vmmRpc.stopVm({ id: vm.id });
    loadVMList();
  }

  async function removeVm(id: string) {
    if (localStorage.getItem('dangerConfirm') === 'true' &&
        !confirm('Remove VM? This action cannot be undone.')) {
      return;
    }
    await vmmRpc.removeVm({ id });
    loadVMList();
  }

  function showLogs(id: string, channel: string) {
    window.open(`/logs?id=${encodeURIComponent(id)}&follow=false&ansi=false&lines=200&ch=${channel}`, '_blank');
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

    // Check KMS
    const kmsEnabled = vm.appCompose?.kms_enabled || vm.appCompose?.features?.includes('kms') ||
                     vm.configuration?.kms_urls?.length > 0;
    if (kmsEnabled) features.push("kms");

    // Check Gateway/TProxy
    const gatewayEnabled = vm.appCompose?.gateway_enabled || vm.appCompose?.tproxy_enabled ||
                          vm.appCompose?.features?.includes('tproxy-net') || vm.configuration?.gateway_urls?.length > 0;
    if (gatewayEnabled) features.push("gateway");

    // Check other features from appCompose
    if (vm.appCompose?.public_logs) features.push("logs");
    if (vm.appCompose?.public_sysinfo) features.push("sysinfo");
    if (vm.appCompose?.public_tcbinfo) features.push("tcbinfo");

    return features.length > 0 ? features.join(', ') : 'None';
  }

  onMounted(() => {
    watchVmList();
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
  };
}

export { useVmManager };
