# Contributing

Thank you for your interest in contributing to this project!

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
