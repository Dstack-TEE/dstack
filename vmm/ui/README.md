# dstack Console UI

This directory contains the source for the Vue-based VM management console.

## Usage

```bash
# Install dev dependencies (installs protobufjs CLI)
npm install

# Build the beta console once
npm run build

# Build continuously (writes beta console on changes)
npm run watch
```

The build step generates a single-file HTML artifact at `../src/console_beta.html`
which is served by `dstack-vmm` under the `/beta` path. The existing
`console.html` remains untouched so both versions can coexist.

The UI codebase is written in TypeScript. The build pipeline performs three steps:

1. `scripts/build_proto.sh` (borrowed from `phala-blockchain`) uses `pbjs/pbts` to regenerate static JS bindings for `vmm_rpc.proto`.
2. `tsc` transpiles `src/**/*.ts` into `build/ts/`.
3. `build.mjs` bundles the transpiled output together with the runtime assets into a single HTML page `console_beta.html`.
