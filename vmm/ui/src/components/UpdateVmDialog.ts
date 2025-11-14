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
    kmsEnabled: { type: Boolean, required: true },
    composeHashPreview: { type: String, required: true },
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

        <div v-if="kmsEnabled">
          <div class="form-group">
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
              <label for="upgradePrelauncher">Pre-launch Script</label>
              <textarea id="upgradePrelauncher" v-model="dialog.preLaunchScript" placeholder="Optional: Bash script to run before starting containers"></textarea>
            </div>
            <div class="app-id-preview">
              Compose Hash: 0x{{ composeHashPreview }}
            </div>
          </div>

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
          <port-mapping-editor :ports="dialog.ports" />
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
