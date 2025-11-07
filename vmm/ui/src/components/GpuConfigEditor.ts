// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
// SPDX-License-Identifier: Apache-2.0

declare const Vue: any;
const { computed } = Vue;

type ComponentInstance = {
  availableGpus: Array<{ slot: string; description?: string; is_free?: boolean }>;
  gpus: string[];
  attachAll: boolean;
};

const GpuConfigEditorComponent = {
  name: 'GpuConfigEditor',
  props: {
    availableGpus: {
      type: Array,
      required: true,
    },
    gpus: {
      type: Array,
      required: true,
    },
    attachAll: {
      type: Boolean,
      required: true,
    },
    allowAttachAll: {
      type: Boolean,
      required: true,
    },
  },
  emits: ['update:gpus', 'update:attachAll'],
  setup(props: any, { emit }: any) {
    const selectedGpus = computed({
      get: () => props.gpus,
      set: (value: string[]) => emit('update:gpus', value),
    });

    const attachAllComputed = computed({
      get: () => props.attachAll,
      set: (value: boolean) => emit('update:attachAll', value),
    });

    return {
      selectedGpus,
      attachAllComputed,
    };
  },
  template: /* html */ `
    <div class="gpu-config-editor">
      <label class="gpu-section-label">GPU Configuration</label>
      <div v-if="allowAttachAll" class="checkbox-grid">
        <label>
          <input type="checkbox" v-model="attachAllComputed">
          Attach All GPUs and NVSwitches
        </label>
      </div>
      <div v-if="!attachAllComputed" class="gpu-config-list">
        <div class="gpu-config-list-header">
          Select GPUs to attach:
        </div>
        <div class="gpu-config-items">
          <label v-for="gpu in availableGpus" :key="gpu.slot">
            <input type="checkbox" :value="gpu.slot" v-model="selectedGpus">
            <span>{{ gpu.slot }}: {{ gpu.description }} {{ gpu.is_free ? '' : '(in use)' }}</span>
          </label>
        </div>
      </div>
      <div v-else class="gpu-config-hint">
        All NVIDIA GPUs and NVSwitches will be attached to the VM
      </div>
    </div>
  `,
};

export = GpuConfigEditorComponent;
