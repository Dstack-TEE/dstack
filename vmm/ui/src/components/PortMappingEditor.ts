// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
// SPDX-License-Identifier: Apache-2.0

type PortEntry = {
  protocol: string;
  host_address: string;          // Actual address sent to backend
  host_address_mode?: string;    // "local" | "public" | "custom"
  host_port: number | null;
  vm_port: number | null;
  custom_ip?: string;            // User-entered IP for custom mode
};

type ComponentInstance = {
  ports: PortEntry[];
};

const PortMappingEditorComponent = {
  name: 'PortMappingEditor',
  props: {
    ports: {
      type: Array,
      required: true,
    },
  },
  template: /* html */ `
    <div class="port-mapping-editor">
      <label>Port Mappings</label>
      <div v-for="(port, index) in ports" :key="index" class="port-row">
        
        <!-- protocol -->
        <select v-model="port.protocol">
          <option value="tcp">TCP</option>
          <option value="udp">UDP</option>
        </select>

        <!-- address mode selector -->
        <select v-model="port.host_address_mode" @change="onModeChange(port)">
          <option value="local">Local</option>
          <option value="public">Public</option>
          <option value="custom">Custom</option>
        </select>

        <!-- custom IP input -->
        <input 
          v-if="port.host_address_mode === 'custom'"
          type="text"
          v-model="port.custom_ip"
          placeholder="Enter IP address"
          @input="onCustomIPChange(port)"
        />

        <!-- ports -->
        <input type="number" v-model.number="port.host_port" placeholder="Host Port" required>
        <input type="number" v-model.number="port.vm_port" placeholder="VM Port" required>

        <!-- remove -->
        <button type="button" class="action-btn danger" @click="removePort(index)">
          Remove
        </button>
      </div>

      <!-- add -->
      <button type="button" class="action-btn" @click="addPort">
        Add Port
      </button>
    </div>
  `,

  methods: {
    addPort(this: ComponentInstance) {
      this.ports.push({
        protocol: 'tcp',
        host_address: '127.0.0.1',
        host_address_mode: 'local',
        custom_ip: '',
        host_port: null,
        vm_port: null,
      });
    },

    removePort(this: ComponentInstance, index: number) {
      this.ports.splice(index, 1);
    },

    // Called when switching between Local / Public / Custom
    onModeChange(port: PortEntry) {
      if (port.host_address_mode === 'local') {
        port.host_address = '127.0.0.1';
      } 
      else if (port.host_address_mode === 'public') {
        port.host_address = '0.0.0.0';
      } 
      else if (port.host_address_mode === 'custom') {
        port.host_address = port.custom_ip || '';
      }
    },

    // Called when user types a custom IP
    onCustomIPChange(port: PortEntry) {
      if (port.host_address_mode === 'custom') {
        port.host_address = port.custom_ip || '';
      }
    },
  },
};

export = PortMappingEditorComponent;
