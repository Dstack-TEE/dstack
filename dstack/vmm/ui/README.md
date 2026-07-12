# dstack Console UI

This directory contains the source for the Vue-based VM management console.

## Usage

```bash
# cargo build will run the UI build automatically
cargo build -p dstack-vmm

# Build continuously (writes console_v1 on changes)
npm install
npm run watch
```

`dstack-vmm` now builds the single-file HTML artifact from `build.rs` and writes it
to Cargo's `OUT_DIR`. This requires Node.js and npm to be installed; if they are
missing, the Rust build will fail with an installation hint. The previous
`console_v0.html` remains untouched so the legacy UI stays available under `/v0`.

The UI codebase is written in TypeScript. The build pipeline performs three steps:

1. `scripts/build_proto.sh` (borrowed from `phala-blockchain`) uses `pbjs/pbts` to regenerate static JS bindings for `vmm_rpc.proto`.
2. `tsc` transpiles `src/**/*.ts` into `build/ts/`.
3. `build.mjs` bundles the transpiled output together with the runtime assets into a single HTML page `console_v1.html`.
