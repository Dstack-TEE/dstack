// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import { defineConfig } from "tsup"

export default defineConfig({
  entry: [
    "src/index.ts",
    "src/viem.ts",
    "src/solana.ts",
    "src/encrypt-env-vars.ts",
    "src/get-compose-hash.ts",
    "src/verify-env-encrypt-public-key.ts",
  ],
  format: ["cjs", "esm"],
  dts: true,
  clean: true,
  sourcemap: false,
  splitting: false,
  treeshake: true,
  target: "es2020",
})
