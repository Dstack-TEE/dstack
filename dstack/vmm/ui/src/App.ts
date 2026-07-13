// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
// SPDX-License-Identifier: Apache-2.0

const EncryptedEnvEditor = require('./components/EncryptedEnvEditor');
const PortMappingEditor = require('./components/PortMappingEditor');
const GpuConfigEditor = require('./components/GpuConfigEditor');
const CreateVmDialog = require('./components/CreateVmDialog');
const UpdateVmDialog = require('./components/UpdateVmDialog');
const ForkVmDialog = require('./components/ForkVmDialog');
const { useVmManager } = require('./composables/useVmManager');
const template: string = require('./templates/app.html');

const AppComponent = {
  name: 'DstackConsoleApp',
  components: {
    'encrypted-env-editor': EncryptedEnvEditor,
    'port-mapping-editor': PortMappingEditor,
    'gpu-config-editor': GpuConfigEditor,
    'create-vm-dialog': CreateVmDialog,
    'update-vm-dialog': UpdateVmDialog,
    'fork-vm-dialog': ForkVmDialog,
  },
  setup() {
    return useVmManager();
  },
  template,
};

export = AppComponent;
