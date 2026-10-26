// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
// SPDX-License-Identifier: Apache-2.0

declare const FileReader: any;

type EnvVar = { key: string; value: string };

type ComponentInstance = {
  envVars: EnvVar[];
  $refs: { envFileInput?: HTMLInputElement };
  $data: {
    editMode: 'form' | 'text';
    textContent: string;
  };
  parseTextContent(): void;
};

const EncryptedEnvEditorComponent = {
  name: 'EncryptedEnvEditor',
  props: {
    envVars: {
      type: Array,
      required: true,
    },
  },
  data() {
    return {
      editMode: 'form' as 'form' | 'text',
      textContent: '',
    };
  },
  template: /* html */ `
    <div class="encrypted-env-editor">
      <div class="env-editor-header">
        <h4 class="env-editor-title">Encrypted Environment Variables</h4>
        <div class="env-mode-toggle">
          <button
            type="button"
            class="mode-btn"
            :class="{ active: editMode === 'form' }"
            @click="switchToForm">
            Form
          </button>
          <button
            type="button"
            class="mode-btn"
            :class="{ active: editMode === 'text' }"
            @click="switchToText">
            Text
          </button>
        </div>
      </div>

      <div v-if="editMode === 'form'" class="env-form-mode">
        <div v-if="envVars.length === 0" class="env-editor-empty">
          <p class="hint">No environment variables yet. Click "Add" to create one.</p>
        </div>
        <div v-for="(env, index) in envVars" :key="index" class="encrypted-env-row">
          <input type="text" v-model="env.key" placeholder="Variable name" required>
          <input type="password" v-model="env.value" placeholder="Value" required>
          <button type="button" class="action-btn danger" @click="removeEnv(index)">
            Remove
          </button>
        </div>
        <div class="encrypted-env-actions">
          <button type="button" class="action-btn" @click="addEnv">Add</button>
          <input type="file" ref="envFileInput" @change="loadEnvFromFile" accept=".env,.txt">
          <button type="button" class="action-btn" @click="triggerFileInput">Load from file</button>
        </div>
      </div>

      <div v-else class="env-text-mode">
        <textarea
          v-model="textContent"
          @blur="parseTextContent"
          placeholder="Enter environment variables, one per line:&#10;KEY1=value1&#10;KEY2=value2&#10;# Comments start with #"
          rows="8"
        ></textarea>
        <p class="hint">Format: KEY=VALUE (one per line). Lines starting with # are ignored.</p>
      </div>
    </div>
  `,
  methods: {
    addEnv(this: ComponentInstance) {
      this.envVars.push({ key: '', value: '' });
    },
    removeEnv(this: ComponentInstance, index: number) {
      this.envVars.splice(index, 1);
    },
    triggerFileInput(this: ComponentInstance) {
      this.$refs.envFileInput?.click();
    },
    switchToForm(this: ComponentInstance) {
      this.parseTextContent();
      this.$data.editMode = 'form';
    },
    switchToText(this: ComponentInstance) {
      this.$data.textContent = this.envVars
        .map((env) => `${env.key}=${env.value}`)
        .join('\n');
      this.$data.editMode = 'text';
    },
    parseTextContent(this: ComponentInstance) {
      const content = this.$data.textContent;
      if (!content.trim()) {
        return;
      }
      const lines = content.split('\n');
      this.envVars.splice(0, this.envVars.length);
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) {
          continue;
        }
        const equalIndex = trimmed.indexOf('=');
        if (equalIndex === -1) {
          continue;
        }
        const key = trimmed.substring(0, equalIndex).trim();
        const value = trimmed.substring(equalIndex + 1).trim();
        if (!key) {
          continue;
        }
        this.envVars.push({ key, value });
      }
    },
    loadEnvFromFile(this: ComponentInstance, event: Event) {
      const input = event.target as HTMLInputElement | null;
      const file = input?.files?.[0];
      if (!file) {
        return;
      }
      const reader = new FileReader();
      reader.onload = (e: { target: { result: string } }) => {
        const content = e.target.result || '';
        const lines = content.split('\n');
        this.envVars.splice(0, this.envVars.length);
        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed || trimmed.startsWith('#')) {
            continue;
          }
          const equalIndex = trimmed.indexOf('=');
          if (equalIndex === -1) {
            continue;
          }
          const key = trimmed.substring(0, equalIndex).trim();
          const value = trimmed.substring(equalIndex + 1).trim();
          if (!key) {
            continue;
          }
          this.envVars.push({ key, value });
        }
      };
      reader.readAsText(file);
      if (input) {
        input.value = '';
      }
    },
  },
};

export = EncryptedEnvEditorComponent;
