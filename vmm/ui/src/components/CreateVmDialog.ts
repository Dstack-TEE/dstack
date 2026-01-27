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
              <label for="initScript">Init Script
                <span class="help-icon" title="Executed before dockerd starts. Use for early system setup.">?</span>
              </label>
              <textarea id="initScript" v-model="form.initScript" placeholder="Optional script executed before dockerd startup" rows="4"></textarea>
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
              </select>
            </div>

            <div class="form-group full-width" v-if="form.key_provider !== 'none'">
              <label for="keyProviderId">Key Provider ID</label>
              <input id="keyProviderId" v-model="form.key_provider_id" type="text" placeholder="Optional provider ID">
            </div>

            <div class="form-group full-width">
              <label>Features</label>
              <div class="feature-checkboxes">
                <label><input type="checkbox" v-model="form.gateway_enabled"> Enable dstack-gateway</label>
                <label><input type="checkbox" v-model="form.public_logs"> Public logs</label>
                <label><input type="checkbox" v-model="form.public_sysinfo"> Public sysinfo</label>
                <label><input type="checkbox" v-model="form.public_tcbinfo"> Public TCB info</label>
                <label><input type="checkbox" v-model="form.no_tee"> Disable TDX</label>
                <label><input type="checkbox" v-model="form.pin_numa"> Pin NUMA</label>
                <label><input type="checkbox" v-model="form.hugepages"> Huge pages</label>
              </div>
            </div>

            <div class="form-group full-width" v-if="form.key_provider === 'kms'">
              <encrypted-env-editor :env-vars="form.encryptedEnvs" />
            </div>

            <div class="form-group full-width" v-if="portMappingEnabled">
              <port-mapping-editor :ports="form.ports" />
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
