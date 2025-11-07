// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
// SPDX-License-Identifier: Apache-2.0

const ForkVmDialogComponent = {
  name: 'ForkVmDialog',
  props: {
    visible: { type: Boolean, required: true },
    dialog: { type: Object, required: true },
    availableImages: { type: Array, required: true },
  },
  emits: ['close', 'submit'],
  template: /* html */ `
    <div v-if="visible" class="dialog-overlay" @click.self="$emit('close')">
      <div class="dialog">
        <h3>Derive VM</h3>
        <p class="warning-text">
          This will create a new VM instance with the same app id, but the disk state will NOT migrate to the new instance.
        </p>

        <div class="form-group">
          <label for="forkImage">Image</label>
          <select id="forkImage" v-model="dialog.image" required>
            <option value="" disabled>Select an image</option>
            <option v-for="image in availableImages" :key="image.name" :value="image.name">
              {{ image.name }}
            </option>
          </select>
        </div>

        <div class="form-group">
          <label for="forkVcpu">Number of vCPUs</label>
          <input id="forkVcpu" v-model.number="dialog.vcpu" type="number" placeholder="vCPUs" required>
        </div>

        <div class="form-group">
          <label for="forkMemory">Memory (MB)</label>
          <input id="forkMemory" v-model.number="dialog.memory" type="number" placeholder="Memory in MB" required>
        </div>

        <div class="form-group">
          <label for="forkDiskSize">Disk Size (GB)</label>
          <input id="forkDiskSize" v-model.number="dialog.disk_size" type="number" placeholder="Disk size in GB" required>
        </div>

        <div class="form-group">
          <label for="forkDiskType">Disk Type</label>
          <select id="forkDiskType" v-model="dialog.disk_type">
            <option value="virtio-pci">Virtio PCI</option>
            <option value="nvme">NVMe</option>
          </select>
        </div>

        <div class="dialog-footer">
          <button class="action-btn primary" @click="$emit('submit')">Derive</button>
          <button class="action-btn" @click="$emit('close')">Cancel</button>
        </div>
      </div>
    </div>
  `,
};

export = ForkVmDialogComponent;
