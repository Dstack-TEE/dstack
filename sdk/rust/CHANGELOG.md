# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.3](https://github.com/Dstack-TEE/dstack/compare/dstack-sdk-v0.1.2...dstack-sdk-v0.1.3) - 2026-05-19

### Added

- *(sdk)* add version() API to all SDKs (Rust, Go, Python, JS)
- *(sdk)* Add /run socket paths for compatibility

### Fixed

- *(ci)* restore simulator test stability
- Move socket to /var/run/dstack/ directory for Docker mount compatibility

### Other

- *(rust)* drop hickory-dns from reqwest features
- cargo fmt
- add tests for k256 compat, version API, and algorithm validation
- Merge remote-tracking branch 'ds/master' into gateway-wavekv
- Merge remote-tracking branch 'ds/master' into refactor-for-cloud-providers
- refactor attestation for multi-provider support
- Fix tests
- Merge branch 'master' into vms
- Add support for Sign/Verify to SDK
