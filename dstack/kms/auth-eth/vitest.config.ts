// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    // The Foundry project shares this directory; keep vitest away from the
    // JavaScript under lib/ (contract dependencies) and the build outputs.
    include: ['*.test.ts'],
  },
});
