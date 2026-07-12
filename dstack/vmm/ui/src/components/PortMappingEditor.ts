// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
// SPDX-License-Identifier: Apache-2.0

type PortEntry = {
  protocol: string;
  host_address: string;
  host_address_mode?: string;    // "local" | "public" | "custom"
  host_port: number | null;
  vm_port: number | null;
  custom_ip?: string;            // User-entered IP for custom mode
};

// ... keep your types as-is ...

type ComponentInstance = {
  ports: PortEntry[];
  normalizePort: (p: PortEntry) => void;
};

const PortMappingEditorComponent = {
  name: 'PortMappingEditor',
  props: {
    ports: { type: Array, required: true },
  },

  // normalize on initial load
  created(this: ComponentInstance) {
    this.ports.forEach((p) => this.normalizePort(p));
  },

  // normalize again if parent replaces ports array (e.g. after refresh)
  watch: {
    ports: {
      deep: true,
      handler(this: ComponentInstance, newPorts: PortEntry[]) {
        newPorts.forEach((p) => this.normalizePort(p));
      },
    },
  },

  template: /* html */ `
    <div class="port-mapping-editor">
      <label>Port Mappings</label>
      <div v-for="(port, index) in ports" :key="index" class="port-row">
        <select v-model="port.protocol">
          <option value="tcp">TCP</option>
          <option value="udp">UDP</option>
        </select>

        <select v-model="port.host_address_mode" @change="onModeChange(port)">
          <option value="local">Local</option>
          <option value="public">Public</option>
          <option value="custom">Custom</option>
        </select>

        <input 
          v-if="port.host_address_mode === 'custom'"
          type="text"
          v-model="port.custom_ip"
          placeholder="Enter IP address"
          @input="onCustomIPChange(port)"
        />

        <input type="number" v-model.number="port.host_port" placeholder="Host Port" required>
        <input type="number" v-model.number="port.vm_port" placeholder="VM Port" required>
        <button type="button" class="action-btn danger" @click="removePort(index)">Remove</button>
      </div>
      <button type="button" class="action-btn" @click="addPort">Add Port</button>
    </div>
  `,

  methods: {
    // derives mode + custom_ip from host_address when editing existing VMs
    normalizePort(this: ComponentInstance, port: PortEntry) {
      // If mode already set, keep it (don’t fight the user while editing)
      if (port.host_address_mode) return;

      if (port.host_address === '127.0.0.1') {
        port.host_address_mode = 'local';
        port.custom_ip = '';
      } else if (port.host_address === '0.0.0.0') {
        port.host_address_mode = 'public';
        port.custom_ip = '';
      } else {
        port.host_address_mode = 'custom';
        port.custom_ip = port.host_address; // show dedicated IP in input
      }
    },

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

    onModeChange(port: PortEntry) {
      if (port.host_address_mode === 'local') {
        port.host_address = '127.0.0.1';
        port.custom_ip = '';
      } else if (port.host_address_mode === 'public') {
        port.host_address = '0.0.0.0';
        port.custom_ip = '';
      } else if (port.host_address_mode === 'custom') {
        // if coming from existing custom, keep it; otherwise start empty
        if (!port.custom_ip || port.custom_ip === '') {
          // if host_address already contains a non-standard IP, reuse it
          if (port.host_address !== '127.0.0.1' && port.host_address !== '0.0.0.0') {
            port.custom_ip = port.host_address;
          }
        }
        port.host_address = port.custom_ip || '';
      }
    },

    onCustomIPChange(port: PortEntry) {
      if (port.host_address_mode === 'custom') {
        port.host_address = port.custom_ip || '';
      }
    },
  },
};

export = PortMappingEditorComponent;
