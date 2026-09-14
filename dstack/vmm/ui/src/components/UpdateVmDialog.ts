// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
// SPDX-License-Identifier: Apache-2.0

const EncryptedEnvEditor = require('./EncryptedEnvEditor');
const PortMappingEditor = require('./PortMappingEditor');
const GpuConfigEditor = require('./GpuConfigEditor');

const UpdateVmDialogComponent = {
  name: 'UpdateVmDialog',
  components: {
    'encrypted-env-editor': EncryptedEnvEditor,
    'port-mapping-editor': PortMappingEditor,
    'gpu-config-editor': GpuConfigEditor,
  },
  props: {
    visible: { type: Boolean, required: true },
    dialog: { type: Object, required: true },
    availableImages: { type: Array, required: true },
    availableGpus: { type: Array, required: true },
    allowAttachAllGpus: { type: Boolean, required: true },
    portMappingEnabled: { type: Boolean, required: true },
    networkingModes: { type: Array, required: true },
    defaultBridge: { type: String, default: '' },
    maxNetQueues: { type: Number, default: 0 },
    defaultNetworkingLabel: { type: String, required: true },
    defaultModeTunable: { type: Boolean, default: false },
    defaultVhostOn: { type: Boolean, default: false },
    kmsEnabled: { type: Boolean, required: true },
    composeHashPreview: { type: String, required: true },
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
        <h3>Update VM Config</h3>

        <div v-if="kmsEnabled">
          <div class="form-group">
            <label for="upgradeVcpu">Number of vCPUs</label>
            <input id="upgradeVcpu" v-model.number="dialog.vcpu" type="number" placeholder="vCPUs" required>
          </div>
          <div class="form-group">
            <label for="upgradeMemory">Memory</label>
            <div class="inline-field">
              <input id="upgradeMemory" v-model.number="dialog.memoryValue" type="number" placeholder="Memory" required>
              <select v-model="dialog.memoryUnit">
                <option value="MB">MB</option>
                <option value="GB">GB</option>
              </select>
            </div>
          </div>
        </div>

        <div v-if="kmsEnabled" class="form-group">
          <label for="upgradeSwap">Swap (optional)</label>
          <div class="inline-field">
            <input id="upgradeSwap" v-model.number="dialog.swapValue" type="number" min="0" step="0.1" placeholder="Swap size" :disabled="!dialog.updateCompose">
            <select v-model="dialog.swapUnit" :disabled="!dialog.updateCompose">
              <option value="MB">MB</option>
              <option value="GB">GB</option>
            </select>
          </div>
          <small class="hint">Enable "Update compose" to change swap size.</small>
        </div>

        <div class="form-group">
          <label for="upgradeDiskSize">Disk Size (GB)</label>
          <input id="upgradeDiskSize" v-model.number="dialog.disk_size" type="number" placeholder="Disk size in GB" required>
        </div>

        <div v-if="kmsEnabled" class="form-group">
          <label for="upgradeImage">Image</label>
          <select id="upgradeImage" v-model="dialog.image" required>
            <option value="" disabled>Select an image</option>
            <option v-for="image in availableImages" :key="image.name" :value="image.name">
              {{ image.name }}
            </option>
          </select>
        </div>

        <div class="checkbox-grid">
          <label><input type="checkbox" v-model="dialog.updateCompose"> Update App Compose</label>
        </div>

        <div v-if="dialog.updateCompose" class="compose-update">
          <div class="form-group">
            <label for="upgradeCompose">Docker Compose File</label>
            <div class="file-input-row">
              <div class="file-input-actions">
                <button type="button" class="action-btn" @click="$refs.composeFile.click()">Upload File</button>
                <span class="help-text">or paste below</span>
                <input ref="composeFile" type="file" accept=".yml,.yaml,.txt" @change="$emit('load-compose', $event)">
              </div>
              <textarea id="upgradeCompose" v-model="dialog.dockerComposeFile" placeholder="Paste your new docker-compose.yml here" rows="8" required></textarea>
            </div>
          </div>
          <div class="form-group">
            <label>Init Scripts
              <span class="help-icon" title="Executed before dockerd starts. Use for early system setup.">?</span>
            </label>
            <div v-for="(script, index) in dialog.initScripts" :key="index" class="file-input-row">
              <textarea :id="'upgradeInitScript-' + index" v-model="dialog.initScripts[index]" :placeholder="'Init script ' + (index + 1)" rows="3"></textarea>
              <button v-if="dialog.initScripts.length > 1" type="button" class="action-btn danger" @click="dialog.initScripts.splice(index, 1)">Remove</button>
            </div>
            <!-- Keep in sync with dstack_types::MAX_INIT_SCRIPTS. -->
            <button v-if="dialog.initScripts.length < 5" type="button" class="action-btn" @click="dialog.initScripts.push('')">Add Init Script</button>
          </div>
          <div class="form-group">
            <label for="upgradePrelauncher">Pre-launch Script
              <span class="help-icon" title="Executed after dockerd starts, before containers launch.">?</span>
            </label>
            <textarea id="upgradePrelauncher" v-model="dialog.preLaunchScript" placeholder="Optional: Bash script to run before starting containers" rows="3"></textarea>
          </div>
          <div class="app-id-preview">
            Compose Hash: 0x{{ composeHashPreview }}
          </div>
        </div>

        <div v-if="kmsEnabled">
          <div class="checkbox-grid">
            <label><input type="checkbox" v-model="dialog.resetSecrets"> Reset secrets</label>
          </div>
          <div v-if="dialog.resetSecrets" class="reset-secrets">
            <div class="form-group full-width">
              <encrypted-env-editor :env-vars="dialog.encryptedEnvs" />
            </div>
          </div>
        </div>

        <div class="form-group" v-if="availableGpus.length > 0">
          <div class="checkbox-grid">
            <label><input type="checkbox" v-model="dialog.updateGpuConfig"> Update GPU configuration</label>
          </div>
          <div v-if="dialog.updateGpuConfig">
            <gpu-config-editor
              :available-gpus="availableGpus"
              :allow-attach-all="allowAttachAllGpus"
              v-model:gpus="dialog.selectedGpus"
              v-model:attach-all="dialog.attachAllGpus"
            />
          </div>
        </div>

        <div class="form-group full-width" v-if="portMappingEnabled">
          <port-mapping-editor
            :ports="dialog.ports"
            :nic-count="Math.max(dialog.networks.length, 1)"
          />
        </div>

        <div class="form-group full-width">
          <div class="checkbox-grid">
            <label><input type="checkbox" v-model="dialog.updateNetworking"> Update networking</label>
          </div>
          <div v-if="dialog.updateNetworking" class="network-config-editor">
            <div v-if="!dialog.networks.length" class="network-config-empty">{{ defaultNetworkingLabel }}</div>
            <div v-for="(network, index) in dialog.networks" :key="index" class="network-config-row">
              <select v-model="network.mode">
                <option :value="''">Node default</option>
                <option v-for="mode in networkingModes" :key="mode" :value="mode">
                  {{ mode.charAt(0).toUpperCase() + mode.slice(1) }}
                </option>
                <!-- A VM keeps the backend it was deployed on even after node
                     policy stops offering it. Without this the select renders
                     blank while the model still holds the old mode, so the row
                     looks unset and submitting fails on a value nobody chose. -->
                <option
                  v-if="network.mode && !networkingModes.includes(network.mode)"
                  :value="network.mode"
                >
                  {{ network.mode.charAt(0).toUpperCase() + network.mode.slice(1) }} (no longer offered)
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
              <button type="button" class="action-btn danger" @click="dialog.networks.splice(index, 1)">Remove</button>
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
            <button type="button" class="action-btn" @click="dialog.networks.push({ mode: '', bridge_name: '', vhost: '', queues: '' })">Add Network</button>
          </div>
        </div>

        <div class="form-group">
          <label for="upgradeUserConfig">User Config</label>
          <textarea id="upgradeUserConfig" v-model="dialog.user_config" placeholder="Optional: User config to be put at /dstack/.user-config in the CVM"></textarea>
        </div>

        <div class="dialog-footer">
          <button class="action-btn primary" @click="$emit('submit')">Update</button>
          <button class="action-btn" @click="$emit('close')">Cancel</button>
        </div>
      </div>
    </div>
  `,
};

export = UpdateVmDialogComponent;
