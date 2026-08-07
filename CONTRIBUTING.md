# Contributing

Thank you for your interest in contributing to this project!

## Branches

- `next` is the integration mainline and the default branch. Open every pull
  request against it unless a maintainer asks otherwise.
- `release/v<major>.<minor>.x` carries a released line — `release/v0.5.x` is
  the current one. It only takes fixes cherry-picked back from `next`; do not
  develop on it directly. Patch tags are cut here.

Name a working branch whatever describes it. CI runs on pull requests, so a
branch gets its checks once a PR is open rather than on every push.

The default branch was renamed from `master` to `next`. Web links, raw file
URLs, and the REST API redirect, but the old ref name is gone at the git
level: `git fetch origin master` and `git clone -b master` now fail. Update an
existing clone with:

```bash
git branch -m master next
git fetch origin
git branch -u origin/next next
git remote set-head origin -a
```

## Development

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Commit your changes using conventional commits
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

## Repository layout

- `dstack/` contains the core Rust workspace and component-owned assets. Keep a
  component's build, deployment, test, and API documentation next to that
  component when it is not useful outside the component.
- `sdk/` contains the public language SDKs and simulator.
- `os/` contains the backend-neutral guest-OS contract, image assembly, common
  guest payload, and backend implementations. A file under `os/<backend>/`
  must be specific to that backend.
- `docs/` contains repository-wide developer, operator, architecture, and
  security documentation. Do not put a product guide at the repository root.
- `examples/` contains supported end-user examples.
- `tools/` contains cross-component developer/operator utilities. Put a script
  here instead of under an OS backend when it also builds or configures the
  host, deploys services, or operates on multiple components.
- `.github/` contains GitHub Actions workflows and workflow-only helpers.

Use the narrowest owning directory. Fixture explanations and component
READMEs should stay with their fixtures/components; general guides should be
linked from the root README and live under `docs/`.

## Test a guest without TEE hardware

Development images include the extensible `dstack-tee-simulator`. Its default
platform backend is TDX. On a VM launched with `no_tee`, that backend exposes
the Linux interfaces used by the normal guest software:

- configfs-tsm quote generation under `/sys/kernel/config/tsm/report`;
- RTMR extension files used by `tdx-attest`;
- a CCEL boot-event fixture.

This keeps `dstack-prepare`, measurement, encrypted-storage setup, the guest
agent, and attestation APIs on their production code paths. The generated quote
has an intentionally invalid signature, so a production verifier or KMS must
reject it.

The service uses the default TDX backend. For direct simulator development, the
same selection can be made explicitly with `dstack-tee-simulator --platform
tdx`. New TEE platforms are implemented as separate backends behind the shared
simulator lifecycle.

Build or install a `dstack-dev-*` image, then deploy without KMS or gateway:

```bash
dstack deploy ./docker-compose.yml \
  --name no-tee-dev \
  --image dstack-dev-VERSION \
  --no-kms \
  --no-tee
```

To exercise persistent TPM-backed app keys as well, install `swtpm` on the VMM
host and select `key_provider=tpm` in the VMM console (or pass `--key-provider
tpm` in tooling that exposes the compose option). The VMM keeps the software
TPM state in the VM work directory so that seal/unseal survives guest restarts.
The software TPM is host-controlled and does not provide hardware isolation.

The simulator package is installed only in development images. This mode
provides no hardware isolation and must never be used with production
workloads or secrets. Real quote generation, hardware isolation, and KMS
authorization still require TDX or another supported TEE.

## Commit Convention

This project uses [Conventional Commits](https://www.conventionalcommits.org/). Please format your commit messages as:

```
<type>: <description>

[optional body]
```

Examples:
- `feat: add user authentication`
- `fix: resolve memory leak in worker process`
- `docs: update API documentation`

## Changelog

The changelog is automatically generated using [git-cliff](https://git-cliff.org/). To update the changelog:

```bash
git-cliff --output CHANGELOG.md
```

The changelog follows the [Keep a Changelog](https://keepachangelog.com/) format and includes GitHub integration for PR links and contributor recognition.

## License

This project uses SPDX headers for license compliance. You should add appropriate SPDX headers to all your source files.

We have a script to automatically add SPDX headers based on git blame data:

```bash
python3 tools/add-spdx-attribution.py --file path/to/file.rs
```

Before submitting your changes, verify SPDX compliance using the [REUSE tool](https://github.com/fsfe/reuse-tool):

```bash
reuse lint
```
