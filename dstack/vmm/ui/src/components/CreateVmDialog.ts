// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
// SPDX-License-Identifier: Apache-2.0

const EncryptedEnvEditor = require('./EncryptedEnvEditor');
const PortMappingEditor = require('./PortMappingEditor');
const GpuConfigEditor = require('./GpuConfigEditor');

const CreateVmDialogComponent = {
  name: 'CreateVmDialog',
  components: {
    'encrypted-env-editor': EncryptedEnvEditor,
    'port-mapping-editor': PortMappingEditor,
    'gpu-config-editor': GpuConfigEditor,
  },
  props: {
    visible: { type: Boolean, required: true },
    form: { type: Object, required: true },
    availableImages: { type: Array, required: true },
    availableGpus: { type: Array, required: true },
    allowAttachAllGpus: { type: Boolean, required: true },
    kmsAvailable: { type: Boolean, required: true },
    portMappingEnabled: { type: Boolean, required: true },
    networkingModes: { type: Array, required: true },
    defaultBridge: { type: String, default: '' },
    maxNetQueues: { type: Number, default: 0 },
    defaultNetworkingLabel: { type: String, required: true },
    defaultModeTunable: { type: Boolean, default: false },
    defaultVhostOn: { type: Boolean, default: false },
  },
  methods: {
    // Whether this NIC will end up on the vhost data plane. An unset select
    // means it follows the node, and a node with vhost off gives one queue pair
    // however many vCPUs the VM has -- so the answer is not readable from this
    // row alone.
    vhostOn(network: { vhost?: string }) {
      if (network.vhost === 'on') {
        return true;
      }
      if (network.vhost === 'off') {
        return false;
      }
      return (this as any).defaultVhostOn;
    },
    // What an empty queues field actually resolves to. It is the vCPU count
    // only when vhost is on: with vhost off the backend has no multiqueue data
    // plane and the NIC gets exactly one queue pair.
    queuesHint(network: { vhost?: string }) {
      if (!this.vhostOn(network)) {
        return 'virtio-net queue pairs. Empty means one queue pair, because vhost is off.';
      }
      const cap = (this as any).maxNetQueues
        ? `, capped at ${(this as any).maxNetQueues} on this node`
        : '';
      return `virtio-net queue pairs. Empty follows the VM's vCPU count${cap}.`;
    },
    queuesPlaceholder(network: { vhost?: string }) {
      if (!this.vhostOn(network)) {
        return 'queues: auto (1, vhost off)';
      }
      const cap = (this as any).maxNetQueues ? ` (max ${(this as any).maxNetQueues})` : '';
      return `queues: auto${cap}`;
    },
  },
  emits: ['close', 'submit', 'load-compose'],
  template: /* html */ `
    <div v-if="visible" class="dialog-overlay" @click.self="$emit('close')">
      <div class="dialog">
        <h2>Deploy a new instance</h2>
        <form @submit.prevent="$emit('submit')" class="create-vm-form">
          <div class="form-grid">
            <div class="form-group">
              <label for="vmName">Name</label>
              <input id="vmName" v-model="form.name" type="text" placeholder="Enter VM name" required>
            </div>

            <div class="form-group">
              <label for="vmImage">Image</label>
              <select id="vmImage" v-model="form.image" required>
                <option value="" disabled>Select an image</option>
                <option v-for="image in availableImages" :key="image.name" :value="image.name">
                  {{ image.name }}
                </option>
              </select>
            </div>

            <div class="form-group">
              <label for="vcpu">Number of vCPUs</label>
              <input id="vcpu" v-model.number="form.vcpu" type="number" placeholder="vCPUs" required>
            </div>

            <div class="form-group">
              <label for="memory">Memory</label>
              <div class="inline-field">
                <input id="memory" v-model.number="form.memoryValue" type="number" placeholder="Memory" required>
                <select v-model="form.memoryUnit">
                  <option value="MB">MB</option>
                  <option value="GB">GB</option>
                </select>
              </div>
            </div>

            <div class="form-group">
              <label for="swapSize">Swap (optional)</label>
              <div class="inline-field">
                <input id="swapSize" v-model.number="form.swapValue" type="number" min="0" step="0.1" placeholder="Swap size">
                <select v-model="form.swapUnit">
                  <option value="MB">MB</option>
                  <option value="GB">GB</option>
                </select>
              </div>
              <small class="hint">Leave as 0 to disable swap.</small>
            </div>

            <div class="form-group">
              <label for="diskSize">Storage (GB)</label>
              <input id="diskSize" v-model.number="form.disk_size" type="number" placeholder="Storage size in GB" required>
            </div>

            <div class="form-group">
              <label for="storageFs">Storage Filesystem
                <span class="help-icon" title="ZFS: strong integrity guarantees. ext4: lower overhead for databases.">?</span>
              </label>
              <select id="storageFs" v-model="form.storage_fs">
                <option value="">Default (ZFS)</option>
                <option value="zfs">ZFS</option>
                <option value="ext4">ext4</option>
              </select>
            </div>

            <div class="form-group full-width">
              <label for="appId">App ID (optional)</label>
              <input id="appId" v-model="form.app_id" type="text" placeholder="Leave empty for automatic generation">
            </div>

            <div class="form-group full-width">
              <label for="dockerComposeFile">Docker Compose File</label>
              <div class="file-input-row">
                <div class="file-input-actions">
                  <button type="button" class="action-btn" @click="$refs.composeFile.click()">Upload File</button>
                  <span class="help-text">or paste below</span>
                  <input ref="composeFile" type="file" accept=".yml,.yaml,.txt" @change="$emit('load-compose', $event)">
                </div>
                <textarea id="dockerComposeFile" v-model="form.dockerComposeFile" placeholder="Paste your docker-compose.yml here" rows="8"></textarea>
              </div>
            </div>

            <div class="form-group full-width">
              <label>Init Scripts
                <span class="help-icon" title="Executed before dockerd starts. Use for early system setup.">?</span>
              </label>
              <div v-for="(script, index) in form.initScripts" :key="index" class="file-input-row">
                <textarea :id="'initScript-' + index" v-model="form.initScripts[index]" :placeholder="'Init script ' + (index + 1)" rows="4"></textarea>
                <button v-if="form.initScripts.length > 1" type="button" class="action-btn danger" @click="form.initScripts.splice(index, 1)">Remove</button>
              </div>
              <!-- Keep in sync with dstack_types::MAX_INIT_SCRIPTS. -->
              <button v-if="form.initScripts.length < 5" type="button" class="action-btn" @click="form.initScripts.push('')">Add Init Script</button>
            </div>

            <div class="form-group full-width">
              <label for="preLaunchScript">Pre-launch Script
                <span class="help-icon" title="Executed after dockerd starts, before containers launch.">?</span>
              </label>
              <textarea id="preLaunchScript" v-model="form.preLaunchScript" placeholder="Optional script executed before container launch" rows="4"></textarea>
            </div>

            <div class="form-group full-width">
              <label for="userConfig">User Config</label>
              <textarea id="userConfig" v-model="form.user_config" placeholder="Optional user config placed at /dstack/.user-config in the CVM"></textarea>
            </div>

            <div class="form-group full-width" v-if="availableGpus.length > 0">
              <gpu-config-editor
                :available-gpus="availableGpus"
                v-model:gpus="form.selectedGpus"
                v-model:attach-all="form.attachAllGpus"
                :allow-attach-all="allowAttachAllGpus"
              />
            </div>

            <div class="form-group full-width">
              <label for="keyProviderSelect">Key Provider</label>
              <select id="keyProviderSelect" v-model="form.key_provider">
                <option value="none">None</option>
                <option value="kms">KMS</option>
                <option value="local">Local</option>
                <option value="tpm">TPM</option>
              </select>
            </div>

            <div class="form-group full-width" v-if="form.key_provider === 'kms' || form.key_provider === 'local'">
              <label for="keyProviderId">Key Provider ID</label>
              <input id="keyProviderId" v-model="form.key_provider_id" type="text" placeholder="Optional provider ID">
            </div>

            <div class="form-group full-width">
              <label>Networking</label>
              <div class="network-config-editor">
                <div v-if="!form.networks.length" class="network-config-empty">{{ defaultNetworkingLabel }}</div>
                <div v-for="(network, index) in form.networks" :key="index" class="network-config-row">
                  <select v-model="network.mode">
                    <option :value="''">Node default</option>
                    <option v-for="mode in networkingModes" :key="mode" :value="mode">
                      {{ mode.charAt(0).toUpperCase() + mode.slice(1) }}
                    </option>
                  </select>
                  <input
                    v-if="network.mode === 'bridge'"
                    v-model="network.bridge_name"
                    type="text"
                    aria-label="Bridge name"
                    :placeholder="defaultBridge ? 'Override bridge (empty = ' + defaultBridge + ')' : 'Bridge name'"
                  >
                  <input
                    v-else-if="network.mode === 'macvtap'"
                    v-model="network.parent"
                    type="text"
                    aria-label="Macvtap parent interface"
                    placeholder="Override parent interface (empty = node default)"
                  >
                  <span v-else class="network-config-placeholder"></span>
                  <span v-if="network.mode !== 'user'" class="network-config-tuning">
                    <select v-model="network.vhost" aria-label="vhost-net data plane" title="Kernel vhost-net data plane">
                      <option value="">vhost: default</option>
                      <option value="on">vhost: on</option>
                      <option value="off">vhost: off</option>
                    </select>
                    <input
                      v-model="network.queues"
                      type="number"
                      min="1"
                      :max="maxNetQueues || undefined"
                      aria-label="virtio-net queue pairs"
                      :placeholder="queuesPlaceholder(network)"
                      :title="queuesHint(network)"
                    >
                  </span>
                  <span v-else class="network-config-placeholder"></span>
                  <button type="button" class="action-btn danger" @click="form.networks.splice(index, 1)">Remove</button>
                  <small v-if="network.mode === 'bridge'" class="hint network-config-hint">
                    {{ defaultBridge ? 'Leave empty to use the VMM default bridge from vmm.toml: ' + defaultBridge + '.' : 'No default bridge is configured in vmm.toml; enter a bridge interface name.' }}
                    Guest IP is assigned by host DHCP on that bridge and reported after boot.
                  </small>
                  <small v-else-if="network.mode === 'macvtap'" class="hint network-config-hint">
                    Leave empty to use the macvtap parent from vmm.toml. The forwarding mode stays node-controlled.
                  </small>
                  <small v-else-if="network.mode === '' && !defaultModeTunable" class="hint network-config-hint">
                    {{ defaultNetworkingLabel }} has no vhost-net or multiqueue data plane, so these two settings are recorded
                    but stay dormant until this node's default backend can carry them.
                  </small>
                </div>
                <button type="button" class="action-btn" @click="form.networks.push({ mode: '', bridge_name: '', vhost: '', queues: '' })">Add Network</button>
              </div>
            </div>

            <div class="form-group">
              <label for="eventLogVersion">Event log format
                <span class="help-icon" title="V2 (JCS canonical JSON) enables per-event policy evaluation. V1 is the legacy binary format. Requires guest image with v2 support.">?</span>
              </label>
              <select id="eventLogVersion" v-model.number="form.event_log_version">
                <option :value="1">V1 (legacy binary)</option>
                <option :value="2">V2 (JCS canonical JSON)</option>
              </select>
            </div>

            <div class="form-group full-width">
              <label>Features</label>
              <div class="feature-checkboxes">
                <label><input type="checkbox" v-model="form.gateway_enabled"> Enable dstack-gateway</label>
                <label><input type="checkbox" v-model="form.public_logs"> Public logs</label>
                <label><input type="checkbox" v-model="form.public_sysinfo"> Public sysinfo</label>
                <label><input type="checkbox" v-model="form.public_tcbinfo"> Public TCB info</label>
                <label><input type="checkbox" v-model="form.no_tee"> No TEE</label>
                <label><input type="checkbox" v-model="form.pin_numa"> Pin NUMA</label>
                <label><input type="checkbox" v-model="form.hugepages"> Huge pages</label>
              </div>
            </div>

            <div class="form-group full-width">
              <label for="simulatedTeeSelect">Simulated TEE (development only)</label>
              <select id="simulatedTeeSelect" v-model="form.simulated_tee">
                <option value="">Disabled</option>
                <option value="dstack-tdx">dstack TDX</option>
                <option value="dstack-gcp-tdx">GCP TDX</option>
                <option value="dstack-amd-sev-snp">AMD SEV-SNP</option>
                <option value="dstack-nitro-enclave">AWS Nitro Enclave</option>
                <option value="dstack-aws-nitro-tpm">AWS NitroTPM</option>
              </select>
              <small class="hint">Selecting a platform makes this instance run without hardware TEE. Key provider selection remains independent.</small>
            </div>

            <div class="form-group full-width" v-if="form.key_provider === 'kms'">
              <encrypted-env-editor :env-vars="form.encryptedEnvs" />
            </div>

            <div class="form-group full-width" v-if="portMappingEnabled">
              <port-mapping-editor
                :ports="form.ports"
                :nic-count="Math.max(form.networks.length, 1)"
              />
            </div>
          </div>

          <div class="dialog-footer">
            <button type="submit" class="action-btn primary">Deploy</button>
            <button type="button" class="action-btn" @click="$emit('close')">Cancel</button>
          </div>
        </form>
      </div>
    </div>
  `,
};

export = CreateVmDialogComponent;
