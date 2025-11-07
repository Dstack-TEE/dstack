// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
// SPDX-License-Identifier: Apache-2.0

type PortEntry = {
  protocol: string;
  host_address: string;
  host_port: number | null;
  vm_port: number | null;
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
        <select v-model="port.protocol">
          <option value="tcp">TCP</option>
          <option value="udp">UDP</option>
        </select>
        <select v-model="port.host_address">
          <option value="127.0.0.1">Local</option>
          <option value="0.0.0.0">Public</option>
        </select>
        <input type="number" v-model.number="port.host_port" placeholder="Host Port" required>
        <input type="number" v-model.number="port.vm_port" placeholder="VM Port" required>
        <button type="button" class="action-btn danger" @click="removePort(index)">Remove</button>
      </div>
      <button type="button" class="action-btn" @click="addPort">Add Port</button>
    </div>
  `,
  methods: {
    addPort(this: ComponentInstance) {
      this.ports.push({
        protocol: 'tcp',
        host_address: '127.0.0.1',
        host_port: null,
        vm_port: null,
      });
    },
    removePort(this: ComponentInstance, index: number) {
      this.ports.splice(index, 1);
    },
  },
};

export = PortMappingEditorComponent;
