# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Added TappdClient and show warning. by @Leechael
- Add getComposeHash & verifyEnvEncryptPublicKey by @Leechael
- Support customize timeout. by @Leechael
- Add base to hardhat's predefine networks by @Leechael
- Add logo by @h4x3rotab
- Add kms-builder by @kvinwang
- Add logs to dstack-mr by @kvinwang
- Add crate dstack-mr by @kvinwang
- Add /app-info to gw info endpoint by @kvinwang

### Changed
- Clean up test suite - remove duplicate upgrade tests
- Complete Hardhat removal - migrate to pure Foundry setup
- Migrate Hardhat to Foundry with comprehensive test suite
- Merge pull request #249 from Dstack-TEE/dependabot/npm_and_yarn/kms/auth-eth/multi-0ca592796f by @Leechael in [#249](https://github.com/Dstack-TEE/dstack/pull/249)
- Bump form-data in /kms/auth-eth by @dependabot[bot]
- Merge pull request #223 from Dstack-TEE/feat-js-sdk-backward-compatible by @Leechael in [#223](https://github.com/Dstack-TEE/dstack/pull/223)
- V0.5.0 by @Leechael
- Rename Deterministic Compose Hash to Normalized App Compose by @Leechael
- Make preprocess app compose optional by @Leechael
- Typing for AppCompose by @Leechael
- Determinstic compose hash by @Leechael
- Rename dumpAppCompose to toDeterminsticJson and refactor by @Leechael
- Better migrate plan for legacy APIs by @Leechael
- Pump beta release 0.5.0-beta.2 by @Leechael
- Pump beta release 0.5.0-beta.1 by @Leechael
- Rename. by @Leechael
- Backward compatible. by @Leechael
- Move out send_rpc_request to standalone file. by @Leechael
- Merge pull request #245 from Dstack-TEE/gw-info by @Leechael in [#245](https://github.com/Dstack-TEE/dstack/pull/245)
- Add RPC for Gateway Info by @kvinwang
- Merge pull request #244 from Dstack-TEE/feat-auth-backend-examples by @Leechael in [#244](https://github.com/Dstack-TEE/dstack/pull/244)
- More configurable for auth-mock by @Leechael
- Auth-mock by @Leechael
- Auth-eth-bun by @Leechael
- Merge pull request #248 from Dstack-TEE/dependabot/cargo/tokio-1.46.1 by @h4x3rotab in [#248](https://github.com/Dstack-TEE/dstack/pull/248)
- Bump tokio from 1.44.1 to 1.46.1 by @dependabot[bot]
- Merge pull request #247 from Dstack-TEE/dependabot/npm_and_yarn/kms/auth-eth/openzeppelin/contracts-upgradeable-5.4.0 by @dependabot[bot] in [#247](https://github.com/Dstack-TEE/dstack/pull/247)
- Bump @openzeppelin/contracts-upgradeable in /kms/auth-eth by @dependabot[bot]
- Merge pull request #240 from Dstack-TEE/rename-contracts by @Leechael in [#240](https://github.com/Dstack-TEE/dstack/pull/240)
- Update docs for deploy app by @Leechael
- Rename contracts by @kvinwang
- Merge pull request #242 from Dstack-TEE/readme by @h4x3rotab in [#242](https://github.com/Dstack-TEE/dstack/pull/242)
- Limit height by @h4x3rotab
- Vibe documenting by @h4x3rotab
- Update readme by @h4x3rotab
- Merge pull request #239 from Dstack-TEE/fix-rev-net by @kvinwang in [#239](https://github.com/Dstack-TEE/dstack/pull/239)
- Fix reserved ip allocation by @kvinwang
- Merge pull request #233 from Dstack-TEE/dependabot/npm_and_yarn/kms/auth-eth/multi-a1c2ce69a2 by @kvinwang in [#233](https://github.com/Dstack-TEE/dstack/pull/233)
- Bump brace-expansion in /kms/auth-eth by @dependabot[bot]
- Merge pull request #236 from Dstack-TEE/dependabot/npm_and_yarn/kms/auth-eth/axios-1.10.0 by @kvinwang in [#236](https://github.com/Dstack-TEE/dstack/pull/236)
- Bump axios from 1.7.9 to 1.10.0 in /kms/auth-eth by @dependabot[bot]
- Merge pull request #238 from Dstack-TEE/rm-fields by @kvinwang in [#238](https://github.com/Dstack-TEE/dstack/pull/238)
- Remove more fields in AppInfo by @kvinwang
- Merge pull request #232 from Dstack-TEE/rm-rootfs-hash by @kvinwang in [#232](https://github.com/Dstack-TEE/dstack/pull/232)
- Remove rootfs_hash from TcbInfo by @kvinwang
- Merge pull request #234 from Dstack-TEE/dependabot/npm_and_yarn/kms/auth-eth/fastify-4.29.1 by @h4x3rotab in [#234](https://github.com/Dstack-TEE/dstack/pull/234)
- Bump fastify from 4.29.0 to 4.29.1 in /kms/auth-eth by @dependabot[bot]
- Merge pull request #235 from Dstack-TEE/dependabot/npm_and_yarn/kms/auth-eth/base-x-3.0.11 by @h4x3rotab in [#235](https://github.com/Dstack-TEE/dstack/pull/235)
- Bump base-x from 3.0.10 to 3.0.11 in /kms/auth-eth by @dependabot[bot]
- Update image hash by @kvinwang
- Build prod image by @kvinwang
- Allow default values in VmConfig by @kvinwang
- Merge pull request #229 from Dstack-TEE/kms-builder by @kvinwang in [#229](https://github.com/Dstack-TEE/dstack/pull/229)
- Merge pull request #228 from Dstack-TEE/dstack-mr by @kvinwang in [#228](https://github.com/Dstack-TEE/dstack/pull/228)
- Support hugepages for non-gpu vm by @kvinwang
- Use new dstack-mr implmementation by @kvinwang
- Merge pull request #231 from Dstack-TEE/addr-as-appid by @kvinwang in [#231](https://github.com/Dstack-TEE/dstack/pull/231)
- Add back registered apps by @kvinwang
- Use the contract address as appId by @kvinwang
- Merge pull request #230 from Dstack-TEE/gw-quote by @shelvenzhou in [#230](https://github.com/Dstack-TEE/dstack/pull/230)
- Alias app-info and acme-info under /.dstack/ by @kvinwang
- Cache the quotes on fs by @kvinwang
- Add vm_config in quote report by @kvinwang
- Cargo fmt by @kvinwang
- Add base_domain to AcmeInfoResponse by @kvinwang
- Add endpoint this-node by @kvinwang
- Add quote for zt-tls keys by @kvinwang
- Merge pull request #226 from Dstack-TEE/passwd by @kvinwang in [#226](https://github.com/Dstack-TEE/dstack/pull/226)
- Mount passwd files to data disk by @kvinwang
- Merge pull request #224 from Dstack-TEE/code-of-conduct by @h4x3rotab in [#224](https://github.com/Dstack-TEE/dstack/pull/224)
- Create CODE_OF_CONDUCT.md by @h4x3rotab
- Merge pull request #227 from Dstack-TEE/dependabot/npm_and_yarn/kms/auth-eth/pbkdf2-3.1.3 by @kvinwang in [#227](https://github.com/Dstack-TEE/dstack/pull/227)
- Bump pbkdf2 from 3.1.2 to 3.1.3 in /kms/auth-eth by @dependabot[bot]
- Merge pull request #222 from Dstack-TEE/fix-vmm-cli-set-key-provider-id by @Leechael in [#222](https://github.com/Dstack-TEE/dstack/pull/222)

### Fixed
- Unknown field by @Leechael
- Get appAuthImplementation failed. by @Leechael
- Fix anchors by @h4x3rotab
- Unmatched app_compose when no key provider id. by @Leechael

### Removed
- Remove Foundry build artifacts and update .gitignore

## New Contributors
* @shelvenzhou made their first contribution in [#230](https://github.com/Dstack-TEE/dstack/pull/230)
## [0.5.3] - 2025-06-24

### Added
- Add doc design-and-hardening-decisions.md by @kvinwang
- Add doc cvm-boundaries.md by @kvinwang
- Add ERC-165 support with hardcoded interface IDs by @Leechael
- Add warning for dev kms by @kvinwang
- Add script to config firewall for qemu by @kvinwang

### Changed
- Bump version to 0.5.3 by @kvinwang
- Merge pull request #225 from Dstack-TEE/license by @h4x3rotab in [#225](https://github.com/Dstack-TEE/dstack/pull/225)
- Create LICENSE by @h4x3rotab
- Merge pull request #221 from Dstack-TEE/doc-harden by @kvinwang in [#221](https://github.com/Dstack-TEE/dstack/pull/221)
- Update dcap-qvl to 0.3.0 by @kvinwang
- Default max disk size to 10T by @kvinwang
- Merge pull request #220 from Dstack-TEE/feat-gateway-admin-rpc-get-meta-v05x by @Leechael in [#220](https://github.com/Dstack-TEE/dstack/pull/220)
- Merge pull request #216 from Dstack-TEE/doc-cvm-boundaries by @kvinwang in [#216](https://github.com/Dstack-TEE/dstack/pull/216)
- Merge pull request #215 from Dstack-TEE/sec-guide by @kvinwang in [#215](https://github.com/Dstack-TEE/dstack/pull/215)
- Merge branch 'master' into sec-guide by @kvinwang
- Add security guide by @kvinwang
- Merge pull request #217 from Dstack-TEE/add-reprobuid-note by @kvinwang in [#217](https://github.com/Dstack-TEE/dstack/pull/217)
- Add link to reproducible build by @kvinwang
- Merge pull request #213 from Dstack-TEE/kms-erc-165-support by @Leechael in [#213](https://github.com/Dstack-TEE/dstack/pull/213)
- Remove duplicate code. by @Leechael
- Update kms auth related docs by @Leechael
- Commands in hardhat.config.ts by @Leechael
- Build error. by @Leechael
- Update typechain-types. by @Leechael
- Add C code source URL by @kvinwang
- Add security guide by @kvinwang
- Better deployment script by @kvinwang
- Don't copy symbol link files by @kvinwang
- Merge pull request #212 from Dstack-TEE/impl-up-user-config by @kvinwang in [#212](https://github.com/Dstack-TEE/dstack/pull/212)
- Implement update user_config in UI and CLI by @kvinwang
- Merge pull request #199 from Dstack-TEE/config-fw by @Leechael in [#199](https://github.com/Dstack-TEE/dstack/pull/199)
- Update comments by @kvinwang
- Correct checking symlink existance by @kvinwang
- Merge pull request #207 from Dstack-TEE/gw-rt by @kvinwang in [#207](https://github.com/Dstack-TEE/dstack/pull/207)
- Seperate proxy runtime from Rocket by @kvinwang
- Use jemalloc by @kvinwang
- Merge pull request #210 from Dstack-TEE/vmm-gpu-attach-all-opt by @kvinwang in [#210](https://github.com/Dstack-TEE/dstack/pull/210)
- Optional disable attach all gpus by @kvinwang
- Merge pull request #204 from Dstack-TEE/gw-reload-cert by @kvinwang in [#204](https://github.com/Dstack-TEE/dstack/pull/204)
- Fix unit tests by @kvinwang
- Hot reload TLS certificate by @kvinwang
- Add helper function reload_certs by @kvinwang
- Merge pull request #203 from Dstack-TEE/gw-health by @kvinwang in [#203](https://github.com/Dstack-TEE/dstack/pull/203)
- Add health check endpoint by @kvinwang
- Merge pull request #202 from Dstack-TEE/config-tls-ver by @kvinwang in [#202](https://github.com/Dstack-TEE/dstack/pull/202)
- Cargo fmt by @kvinwang
- Configrable tls version and crypto provider by @kvinwang
- Extract create acceptor to a function by @kvinwang
- Merge pull request #205 from Dstack-TEE/vmm-cfg-id by @kvinwang in [#205](https://github.com/Dstack-TEE/dstack/pull/205)
- Only set mr_config_id for supported images by @kvinwang
- Update dstack version to 0.5.2 in docs by @kvinwang
- Merge branch 'gw-no-status' by @kvinwang in [#198](https://github.com/Dstack-TEE/dstack/pull/198)
- Move rpc status/info to admin port by @kvinwang
- Fix tboot.service in dep by @kvinwang

### Fixed
- Move get_meta to admin API. by @Leechael
- Fix test cases for AppAuth test. by @Leechael

### Removed
- Remove unused field bootstraped from InstanceInfo by @kvinwang
- Remove head from dstack-util show by @kvinwang

## [0.5.2] - 2025-06-04

### Added
- Add optional appAuthImplementation setting in initialize by @Leechael
- Add AI generated cheatsheet. by @Leechael
- Add add deploy factory support to KmsAuth by @Leechael
- Add initializeWithData to AppAuth by @Leechael
- Add debug hints for download_image by @Leechael
- Add gateway_app_id to KMS.GetMetaResponse by @Leechael
- Add get_compose_hash endpoint for compose-hash check. by @Leechael
- Added detail in error message for destination issue debugging. by @Leechael
- Adds docstrings by @tuddman

### Changed
- Dstack v0.5.2 by @kvinwang in [#196](https://github.com/Dstack-TEE/dstack/pull/196)
- Merge pull request #195 from Dstack-TEE/mr_config_id_v2 by @kvinwang in [#195](https://github.com/Dstack-TEE/dstack/pull/195)
- Better way to get td report by @kvinwang
- Implement mr_config_id v2 by @kvinwang
- Merge pull request #181 from Dstack-TEE/feat/gateway-rpc-domain-and-kms-info-enhancements by @kvinwang in [#181](https://github.com/Dstack-TEE/dstack/pull/181)
- Merge pull request #182 from Dstack-TEE/imp-app-auth-contract by @Leechael in [#182](https://github.com/Dstack-TEE/dstack/pull/182)
- Code review feedback. by @Leechael
- Update typechain-types by @Leechael
- Update deploy script & cheatsheet docs. by @Leechael
- _registerAppInternal. by @Leechael
- Remove redundant initialization code. by @Leechael
- Expose app implementation address by @Leechael
- Update generated assets. by @Leechael
- Clippy by @Leechael
- Chore（gateway): Add debug log for AcmeClient. by @Leechael
- Expose more metadata in GetMeta API. by @Leechael
- Fmt by @Leechael
- Allows to configure RPC_DOMAIN optionally by @Leechael
- Merge pull request #177 from Dstack-TEE/cvm-kms-url by @kvinwang in [#177](https://github.com/Dstack-TEE/dstack/pull/177)
- Merge pull request #179 from Dstack-TEE/fix-vmm-cli by @Leechael in [#179](https://github.com/Dstack-TEE/dstack/pull/179)
- Update_vm_env with custom kms_urls by @Leechael
- Support for set kms/gw urls for individual CVM by @kvinwang
- Merge pull request #193 from near-bookrock/master by @kvinwang in [#193](https://github.com/Dstack-TEE/dstack/pull/193)
- Merge branch 'master' into master by @near-bookrock
- Merge pull request #194 from tuddman/rust-sdk-docstrings by @kvinwang in [#194](https://github.com/Dstack-TEE/dstack/pull/194)
- Vmm ui: Fix gpu mode display in upgrade panel by @kvinwang
- Use rbind mount by @kvinwang
- Merge pull request #192 from Dstack-TEE/fix-log-span by @kvinwang in [#192](https://github.com/Dstack-TEE/dstack/pull/192)
- Fix bug in log span by @kvinwang
- Make all fields public by @near-bookrock
- Make tcb_info public by @near-bookrock

### Fixed
- Clippy by @Leechael
- Abi in factory method is incorrect. by @Leechael
- Set ensure_ascii=False when generated compose-hash by @Leechael
- Compatible with custom kms-url and gateway-url by @Leechael

## New Contributors
* @near-bookrock made their first contribution
## [0.5.1] - 2025-05-29

### Added
- Support for enforce key provider id in compose by @kvinwang
- Add deepwiki badge by @h4x3rotab
- Add option to hide tcbinfo from 8090 port by @kvinwang
- Add repobeats analytics by @h4x3rotab

### Changed
- Merge branch 'configid' by @kvinwang in [#190](https://github.com/Dstack-TEE/dstack/pull/190)
- Support for bind key provider by @kvinwang
- Set compose hash to mr_config_id by @kvinwang
- Validate compose_hash according to configid by @kvinwang
- Merge pull request #191 from Dstack-TEE/rm-mr-kp by @kvinwang in [#191](https://github.com/Dstack-TEE/dstack/pull/191)
- Fix typo by @kvinwang
- Merge pull request #187 from Dstack-TEE/kms-clear-cache by @kvinwang in [#187](https://github.com/Dstack-TEE/dstack/pull/187)
- Minor rename by @kvinwang
- Add ensure_admin by @kvinwang
- Add RPC to clear image cache by @kvinwang
- Update to v0.5.1 in README by @kvinwang
- Merge branch 'up-md' by @kvinwang in [#189](https://github.com/Dstack-TEE/dstack/pull/189)
- Update build steps in README by @kvinwang
- Update build steps in README by @kvinwang
- Merge pull request #188 from Dstack-TEE/readme by @h4x3rotab in [#188](https://github.com/Dstack-TEE/dstack/pull/188)
- Merge pull request #186 from Dstack-TEE/rpc-req-id by @kvinwang in [#186](https://github.com/Dstack-TEE/dstack/pull/186)
- Add request id by @kvinwang
- Merge pull request #180 from Dstack-TEE/gw-app-auth by @kvinwang in [#180](https://github.com/Dstack-TEE/dstack/pull/180)
- Add LAUNCH TOKEN by @kvinwang
- Add auth API by @kvinwang
- Merge pull request #183 from Dstack-TEE/md-custom-domain by @kvinwang in [#183](https://github.com/Dstack-TEE/dstack/pull/183)
- Update Custom Domain in README by @kvinwang
- Merge pull request #184 from Dstack-TEE/public-tcbinfo by @kvinwang in [#184](https://github.com/Dstack-TEE/dstack/pull/184)
- Merge pull request #185 from Dstack-TEE/readme by @h4x3rotab in [#185](https://github.com/Dstack-TEE/dstack/pull/185)
- Merge pull request #178 from Dstack-TEE/metrics by @Leechael in [#178](https://github.com/Dstack-TEE/dstack/pull/178)
- Add prometheus metrics API by @kvinwang
- Merge pull request #176 from Dstack-TEE/fix-subvar by @kvinwang in [#176](https://github.com/Dstack-TEE/dstack/pull/176)
- More for the rename by @kvinwang
- Rename mr_image to os_image_hash by @kvinwang
- Update deployment doc by @kvinwang
- Update kms compose file by @kvinwang
- Fix mr_image verification issues by @kvinwang
- Minor rename by @kvinwang
- Cargo fmt by @kvinwang
- Support for the new mr_image model by @kvinwang
- Add mr_image in sys-config.json by @kvinwang
- Update CI config by @kvinwang
- Bump versio to 0.5.1 by @kvinwang
- Auto setulimit by @kvinwang
- Remove dep on openssl by @kvinwang in [#174](https://github.com/Dstack-TEE/dstack/pull/174)

### Fixed
- Missed subvar in deploy-to-vmm.sh script by @Leechael

### Removed
- Remove the unused mr_key_provider by @kvinwang

## [0.5.0] - 2025-05-15

### Added
- Add extend_rtmr3 in tdx-attest by @kvinwang
- Support verity based rootfs by @kvinwang
- Adds build-able TlsKeyConfig by @tuddman
- Add rust client for dstack by @Created-for-a-purpose
- Add extend_rtmr3 in tdx-attest by @kvinwang
- Add inspect API for kms/auth-api by @Leechael
- Added requirements.txt by @Leechael

### Changed
- Fix update compose file by @kvinwang
- Fix mount path by @kvinwang
- Update rust in tproxy docker image to 1.86 by @kvinwang
- Merge pull request #173 from Dstack-TEE/sodiumbox by @kvinwang in [#173](https://github.com/Dstack-TEE/dstack/pull/173)
- Implement sodiumbox by @kvinwang
- Better layout for upgrade pannel by @kvinwang
- Merge pull request #171 from Dstack-TEE/dev-0.5.0 by @kvinwang in [#171](https://github.com/Dstack-TEE/dstack/pull/171)
- Cargo fmt by @kvinwang
- Add venv.sh by @kvinwang
- Upgraded test kms contract by @kvinwang
- Auto update certs on start by @kvinwang
- Rm gpus section when no GPUs by @kvinwang
- Mount overlayfs on /home/root by @kvinwang
- Allow null gpu config by @kvinwang
- Fix clippy by @kvinwang
- Use 0.5.0 base image by @kvinwang
- Allow non-zero mr_config_id by @kvinwang
- Add tproxy_app_id for compatibility by @kvinwang
- Merge remote-tracking branch 'ds/master' into dev-0.5.0 by @kvinwang
- Better layout for Features by @kvinwang
- Fix gpu config issues by @kvinwang
- New gpu config format by @kvinwang
- Load tdx-guest.ko in prepare.sh by @kvinwang
- Fix invalid config in dstack-prepare.service by @kvinwang
- Run dstack-prepare service after chronyd by @kvinwang
- Use ZFS for data partition by @kvinwang in [#159](https://github.com/Dstack-TEE/dstack/pull/159)
- Optional secure time by @kvinwang
- Use extend_rtmr3 from tdx-attest by @kvinwang
- Rename tdxctl to dstack-util by @kvinwang
- Bump version to 0.5.0 by @kvinwang
- Merge pull request #170 from Dstack-TEE/rust-1.86 by @kvinwang in [#170](https://github.com/Dstack-TEE/dstack/pull/170)
- Use rust 1.86 by @kvinwang
- Merge pull request #169 from Dstack-TEE/fix-rust-sdk by @kvinwang in [#169](https://github.com/Dstack-TEE/dstack/pull/169)
- Fix incorrect args in rust-sdk by @kvinwang
- Merge pull request #161 from RizeLabs/feat/dstack-sdk-rust by @kvinwang in [#161](https://github.com/Dstack-TEE/dstack/pull/161)
- Merge pull request #6 from tuddman/rust-sdk-addendum-4 by @nlok5923
- Merge pull request #5 from tuddman/rust-sdk-addendum-3 by @nlok5923
- Merge pull request #4 from tuddman/rust-sdk-addendum-2 by @nlok5923
- Merge pull request #3 from tuddman/rust-sdk-addendum by @nlok5923
- Replace evidence-api with dcap-qvl by @Created-for-a-purpose
- Replace ethers with alloy by @Created-for-a-purpose
- Crate renaming + add readme by @nlok5923
- Merge pull request #1 from Created-for-a-purpose/dstack-sdk-rust by @nlok5923
- Minor cleanup by @Created-for-a-purpose
- Merge pull request #168 from Dstack-TEE/rust-1.86 by @kvinwang in [#168](https://github.com/Dstack-TEE/dstack/pull/168)
- Update Rust in CI to 1.86 by @kvinwang
- Merge pull request #165 from Dstack-TEE/fix-upgrade-btn by @kvinwang in [#165](https://github.com/Dstack-TEE/dstack/pull/165)
- Fix disappeared [Upgrade] button by @kvinwang
- Merge pull request #164 from Dstack-TEE/agent-start-order by @kvinwang in [#164](https://github.com/Dstack-TEE/dstack/pull/164)
- Ensure agent starts before docker by @kvinwang
- Merge pull request #166 from Dstack-TEE/rm-command by @kvinwang in [#166](https://github.com/Dstack-TEE/dstack/pull/166)
- Remove command from the api by @kvinwang
- Merge pull request #160 from Dstack-TEE/api-extend-rtmr3 by @h4x3rotab in [#160](https://github.com/Dstack-TEE/dstack/pull/160)
- Add API EmitEvent by @kvinwang
- Add API EmitEvent by @kvinwang
- Optimize vmm firewall rules by @kvinwang
- Merge pull request #156 from Dstack-TEE/fix-phala-cloud-integration by @Leechael in [#156](https://github.com/Dstack-TEE/dstack/pull/156)
- Gateway app: Optional turning on sync mode by @kvinwang
- Fmt(tdxctl) by @Leechael
- Merge pull request #155 from Dstack-TEE/docs by @h4x3rotab in [#155](https://github.com/Dstack-TEE/dstack/pull/155)
- Update docs by @h4x3rotab
- Merge pull request #154 from Dstack-TEE/app-deploy by @h4x3rotab in [#154](https://github.com/Dstack-TEE/dstack/pull/154)
- [doc] Add app deployment section in deployment.md by @kvinwang

### Fixed
- Ordering and unnecessary import by @tuddman
- Suggested changes by @tuddman
- Fixes PR feedback by @tuddman
- Allowed_app_id comparation for gateway should be case insensitive. by @Leechael
- Deploy scripts. by @Leechael
- Tappd.sock has been rename to dstack.sock by @Leechael
- Use up-to-date package name in docker-compose.yml by @Leechael
- Typechain-types by @Leechael

### Removed
- Remove sodiumoxide from Cargo.toml by @kvinwang

## New Contributors
* @nlok5923 made their first contribution
* @tuddman made their first contribution
* @Created-for-a-purpose made their first contribution
## [0.4.2] - 2025-04-18

### Added
- Support https for prpc client by @kvinwang
- Add client agent API docs by @kvinwang
- Add signature verification in go tests by @kvinwang
- Add back the previous go sdk implementation by @kvinwang
- Add dstack simulator config by @kvinwang
- Add a note on how to access info about Dstack by @HashWarlock
- Add unknown-2035.json by @kvinwang
- Add mr_system by @kvinwang
- Add info API. by @Leechael
- Add ethereum Account transform. by @Leechael
- Add optional dependencies solders & keypair generate support by @Leechael
- Add encryptEnvVars by @Leechael
- Add docs/deployment.md by @kvinwang
- Added view stderr in teepod's builtin console by @Leechael
- Add note about how to view stderr by @Leechael
- Add tproxy setup guide & faq by @Leechael
- Add script to deploy kms to teepod by @kvinwang
- Support ACME_STAGING for the docker by @kvinwang
- Add --build to docker compose by @kvinwang
- Add dbg log by @kvinwang
- Add example code by @kvinwang
- Add Attestation doc by @kvinwang

### Changed
- V0.4.2 by @kvinwang in [#153](https://github.com/Dstack-TEE/dstack/pull/153)
- Merge pull request #152 from Dstack-TEE/fix-status by @kvinwang in [#152](https://github.com/Dstack-TEE/dstack/pull/152)
- Fix status display after CVM updated by @kvinwang
- Merge pull request #149 from Dstack-TEE/pccs_url by @kvinwang in [#149](https://github.com/Dstack-TEE/dstack/pull/149)
- Read pccs_url from env var by @kvinwang
- Merge pull request #150 from Dstack-TEE/prpc-client-https by @kvinwang in [#150](https://github.com/Dstack-TEE/dstack/pull/150)
- Merge pull request #151 from Dstack-TEE/api-doc by @kvinwang in [#151](https://github.com/Dstack-TEE/dstack/pull/151)
- Better config fallback for tproxy_enabled by @kvinwang
- Don't include compose file in brief mode by @kvinwang
- Merge pull request #148 from Dstack-TEE/rename-tapp by @kvinwang in [#148](https://github.com/Dstack-TEE/dstack/pull/148)
- Cargo fmt by @kvinwang
- Rename tapp to app or /dstack by @kvinwang
- Unify dstack agent address getter by @kvinwang
- Rename run_as_tapp to run_in_dstack by @kvinwang
- Rename _tapp-address to _dstack-app-address by @kvinwang
- Fix default agent_port and gateway_urls alias by @kvinwang
- Merge pull request #146 from Dstack-TEE/auto-restart by @kvinwang in [#146](https://github.com/Dstack-TEE/dstack/pull/146)
- Auto restart exited VMs by @kvinwang
- Merge pull request #147 from Dstack-TEE/error-on-wrong-contract by @kvinwang in [#147](https://github.com/Dstack-TEE/dstack/pull/147)
- Kms script: Throw error if app auth not found by @kvinwang
- Merge pull request #145 from Dstack-TEE/cross-tdx-attest by @kvinwang in [#145](https://github.com/Dstack-TEE/dstack/pull/145)
- Make tdx-attest compile on non-linux by @kvinwang
- Merge pull request #144 from Dstack-TEE/rename-sdk by @kvinwang in [#144](https://github.com/Dstack-TEE/dstack/pull/144)
- Js sdk: Warn for  simulator endpoint by @kvinwang
- Refactor python SDK by @kvinwang
- Refactor js sdk by @kvinwang
- Refactor go sdk by @kvinwang
- Merge pull request #142 from Dstack-TEE/renaming by @kvinwang in [#142](https://github.com/Dstack-TEE/dstack/pull/142)
- Merge pull request #143 from Dstack-TEE/simulator by @kvinwang in [#143](https://github.com/Dstack-TEE/dstack/pull/143)
- Use app key to sign the derived key by @kvinwang
- Rename more tappd in comments to guest agent by @kvinwang
- Always generate random tls key by @kvinwang
- One more rename by @kvinwang
- Rename get_eth_key to get_key by @kvinwang
- API backward compatibility for vmm and gw by @kvinwang
- Set mime application/json by @kvinwang
- Rename kms to dstack-kms by @kvinwang
- Rename teepod to dstack-vmm by @kvinwang
- Rename tproxy to dstack-gateway by @kvinwang
- Different handler for v0 and latest by @kvinwang
- Fix service name emittion by @kvinwang
- Add report_data in GetQuote response by @kvinwang
- Rename tappd to dstack-guest-agent by @kvinwang
- Fix file existance check by @kvinwang
- Update safe-write to 0.1.2 by @kvinwang
- Merge pull request #140 from Dstack-TEE/tappd-health by @kvinwang in [#140](https://github.com/Dstack-TEE/dstack/pull/140)
- Don't reuse connections in healthy check client by @kvinwang
- Persistent iptalbes rules by @kvinwang
- Merge pull request #139 from Dstack-TEE/teepod-compat by @kvinwang in [#139](https://github.com/Dstack-TEE/dstack/pull/139)
- Compatible older images by @kvinwang
- Merge pull request #138 from HashWarlock/patch-1 by @h4x3rotab in [#138](https://github.com/Dstack-TEE/dstack/pull/138)
- Merge pull request #137 from Dstack-TEE/gpu-include by @kvinwang in [#137](https://github.com/Dstack-TEE/dstack/pull/137)
- Add gpu whitelist by @kvinwang
- Merge pull request #135 from Dstack-TEE/mr-kms by @kvinwang in [#135](https://github.com/Dstack-TEE/dstack/pull/135)
- Add mr-kms to RTMR3 by @kvinwang
- Merge pull request #134 from Dstack-TEE/teepod-ui-opt by @kvinwang in [#134](https://github.com/Dstack-TEE/dstack/pull/134)
- Auto close dropdown by @kvinwang
- Store page size to localStorage by @kvinwang
- More efficient pagination by @kvinwang
- Add pagination/search and optimize net traffic by @kvinwang
- Support for updating port mapping by @kvinwang
- Merge pull request #133 from Dstack-TEE/cvm-fw by @kvinwang in [#133](https://github.com/Dstack-TEE/dstack/pull/133)
- Add script setting the user net firewall by @kvinwang
- Update deployment.md by @kvinwang
- Validate TCB attributes by @kvinwang
- Default memory size to 2048 by @kvinwang
- Show compose hash in the UI by @kvinwang
- Print watchdog error detail by @kvinwang
- Default max_disk_size to 500GB by @kvinwang
- Merge pull request #132 from Dstack-TEE/vec-reserved-net by @kvinwang in [#132](https://github.com/Dstack-TEE/dstack/pull/132)
- Turns reserved-net into an array by @kvinwang
- Fix used slots detect by @kvinwang
- Update unknown-2035.json by @kvinwang
- Release GPU for exited instances by @kvinwang
- Merge pull request #131 from Dstack-TEE/kms-tcb by @kvinwang in [#131](https://github.com/Dstack-TEE/dstack/pull/131)
- Reject to send keys to outdated TCB nodes by @kvinwang
- Add tcbStatus and advisoryIds to BootInfo by @kvinwang
- Update unknown-2035.json by @kvinwang
- Fix missing mrImage in BootInfo by @kvinwang
- V0.4.1 by @kvinwang
- Merge pull request #130 from Dstack-TEE/refactor-contracts by @kvinwang in [#130](https://github.com/Dstack-TEE/dstack/pull/130)
- Refactor KMS contracts to support the new MRs by @kvinwang
- Add device control by @kvinwang
- Merge pull request #128 from Dstack-TEE/det-rtmr3 by @kvinwang in [#128](https://github.com/Dstack-TEE/dstack/pull/128)
- Teepod ui: no_instance_id if no tproxy by @kvinwang
- Rename fn by @kvinwang
- Support for --no-instance-id by @kvinwang
- Optional instance-id by @kvinwang
- Merge pull request #129 from Dstack-TEE/up-deps by @kvinwang in [#129](https://github.com/Dstack-TEE/dstack/pull/129)
- Update dependencies by @kvinwang
- Merge pull request #110 from Dstack-TEE/sdk-updates by @Leechael in [#110](https://github.com/Dstack-TEE/dstack/pull/110)
- Doc update & release. by @Leechael
- Bump py sdk to 0.1.6 & js sdk to 0.1.11 by @Leechael
- Info API & update docs. by @Leechael
- Udpate sdk docs. by @Leechael
- V0.1.10 by @Leechael
- V0.1.8 by @Leechael
- Helper function for solana Keypair by @Leechael
- Update README.md by @Leechael
- TappdInfo API. by @Leechael
- Merge pull request #127 from Dstack-TEE/teepod-gpu by @kvinwang in [#127](https://github.com/Dstack-TEE/dstack/pull/127)
- Cargo fmt by @kvinwang
- Show slot or product_id for associated device by @kvinwang
- Refresh gpus status while opening deploy panel by @kvinwang
- Filter started vm while restore devices by @kvinwang
- Also release devices after shutdown by @kvinwang
- Auto start vm after created by @kvinwang
- Store allocated device id to instance state by @kvinwang
- Add pin-numa and hugepages by @kvinwang
- Add slot in gpu list by @kvinwang
- Support to start CVM with GPUs by @kvinwang
- Merge pull request #126 from Dstack-TEE/teepod-foreground by @kvinwang in [#126](https://github.com/Dstack-TEE/dstack/pull/126)
- Support for non-detached supervisor by @kvinwang
- Add #[serde(default)] by @kvinwang
- Fix compilation error by @kvinwang
- Add secret pubkey verification by @kvinwang
- Fix pubkey in GetMeta by @kvinwang
- Merge pull request #124 from Dstack-TEE/docs-deployment by @kvinwang in [#124](https://github.com/Dstack-TEE/dstack/pull/124)
- Merge pull request #123 from Dstack-TEE/docs by @kvinwang in [#123](https://github.com/Dstack-TEE/dstack/pull/123)
- Merge branch 'deploy-script' by @kvinwang
- Merge pull request #122 from Dstack-TEE/deploy-script by @kvinwang in [#122](https://github.com/Dstack-TEE/dstack/pull/122)
- Update contracts DB by @kvinwang
- Kms cli: Remove salt from app:deploy by @kvinwang
- Add update-env by @kvinwang
- Better deployment script by @kvinwang
- Support for UDS by @kvinwang
- Refactor kms deployment script by @kvinwang
- Add nextAppId by @kvinwang
- Merge pull request #121 from Dstack-TEE/set-caa by @kvinwang in [#121](https://github.com/Dstack-TEE/dstack/pull/121)
- Recreate acme account if the stored url doesn't matches by @kvinwang
- Add rpc set CAA by @kvinwang
- Support allowed_envs by @kvinwang
- Show mrs after got key if the provider is not KMS by @kvinwang
- Don't compile contracts in docker by @kvinwang
- Use lkp for kms by @kvinwang
- Merge pull request #120 from Dstack-TEE/kp-dockerfile by @kvinwang in [#120](https://github.com/Dstack-TEE/dstack/pull/120)
- Refactor key-provider docker files by @kvinwang
- Update hardhat config by @kvinwang
- Merge pull request #119 from Dstack-TEE/sign-pubkey by @kvinwang in [#119](https://github.com/Dstack-TEE/dstack/pull/119)
- Sign env encrypt pubkey by @kvinwang
- Merge pull request #118 from Dstack-TEE/env-whitelist by @kvinwang in [#118](https://github.com/Dstack-TEE/dstack/pull/118)
- Only allow wihtelisted envs by @kvinwang
- Merge pull request #117 from Dstack-TEE/refactor-shared by @kvinwang in [#117](https://github.com/Dstack-TEE/dstack/pull/117)
- Fix unit tests by @kvinwang
- Only allow wihtelisted envs by @kvinwang
- Refactor host shared files by @kvinwang
- Merge pull request #116 from Dstack-TEE/multiple-urls by @kvinwang in [#116](https://github.com/Dstack-TEE/dstack/pull/116)
- Support for multiple kms and tproxy URLs as fallback by @kvinwang
- Merge pull request #111 from Dstack-TEE/tproxy-p2p by @kvinwang in [#111](https://github.com/Dstack-TEE/dstack/pull/111)
- Degrade some logs to debug level by @kvinwang
- Fix bad wg config by @kvinwang
- Event channel buffer size=1 by @kvinwang
- Switch to use wg pubkey as internal map key by @kvinwang
- Dedup nodes when updating by @kvinwang
- Broadcast sync when CVM registered by @kvinwang
- Add broadcast syncing by @kvinwang
- Always sync self config to node list by @kvinwang
- Recycle staled nodes by @kvinwang
- Move dashboard to admin port by @kvinwang
- Avoid using unsafe port by @kvinwang
- Cert renew timeout 5mins by @kvinwang
- Fix NODE_URL in deploy script by @kvinwang
- Fix host_address parsing by @kvinwang
- Print unsettled challenges by @kvinwang
- Add SUBNET_INDEX in compose file by @kvinwang
- Refactor deploy script by @kvinwang
- Allow multiple tproxy appid by @kvinwang
- Support for config subnet index by @kvinwang
- Exclude broadcast ip by @kvinwang
- Add wg info in net info rpc by @kvinwang
- Show number of connections for cvm by @kvinwang
- Implement new tproxy reg protocol by @kvinwang
- Send all wg servers to client by @kvinwang
- Refactor the config file by @kvinwang
- Fix nodes update by @kvinwang
- Refacto certbot task creation by @kvinwang
- Don't abort on state loading failure by @kvinwang
- Remove app cert from dashboard by @kvinwang
- Add upgrading flag file by @kvinwang
- Better instance-id handling by @kvinwang
- Add connections counter by @kvinwang
- Add proxy nodes info in dashboard by @kvinwang
- Implement sync client by @kvinwang
- Rename tls_domain to rpc_domain by @kvinwang
- Add API update_state by @kvinwang
- Fix dashboard layout by @kvinwang
- Support for multiple servers in the protocol by @kvinwang
- Merge pull request #107 from Dstack-TEE/tproxy-dev by @kvinwang in [#107](https://github.com/Dstack-TEE/dstack/pull/107)
- Add USE_HEAD option by @kvinwang
- Update compose rev by @kvinwang
- User letsencrypt prod api by @kvinwang
- Refine deploy script by @kvinwang
- Add teepod-cli.py by @kvinwang
- Add host_address in portmap RPC by @kvinwang
- Support for localhost by @kvinwang
- Enable certbot by @kvinwang
- Better log by @kvinwang
- Built-in certbot by @kvinwang
- Tune tproxy config by @kvinwang
- Remove debug log by @kvinwang
- Fix default rocket config by @kvinwang
- Add renew hook by @kvinwang
- Add admin RPC by @kvinwang
- Wip by @kvinwang
- Add tappd client by @kvinwang
- Add tapp for tproxy by @kvinwang
- Merge pull request #91 from Dstack-TEE/kms-onchain by @kvinwang in [#91](https://github.com/Dstack-TEE/dstack/pull/91)
- Minor rename by @kvinwang
- Fix unittests by @kvinwang
- Adjust the deployment scripts by @kvinwang
- Support Upgrade for AppAuth by @kvinwang
- Add proxy deployment script by @kvinwang
- Implement OwnableUpgradable by @kvinwang
- Add fn initialize by @kvinwang
- Append some RPC description by @kvinwang
- RPC Comment by @kvinwang
- Minor rename by @kvinwang
- Refined key derivation by @kvinwang
- Update README.md by @kvinwang
- Merge pull request #99 from Dstack-TEE/attestation-doc by @kvinwang in [#99](https://github.com/Dstack-TEE/dstack/pull/99)
- Merge pull request #98 from 0xshawn/key-provider-enhancement by @kvinwang in [#98](https://github.com/Dstack-TEE/dstack/pull/98)
- Make docker restart always and run as daemon by @0xshawn

### Fixed
- Fix sig verification by @kvinwang
- Parse failed on tcb_info by @Leechael
- Test case for solana. by @Leechael
- ToKeypair failed by @Leechael
- Fix typo in doc. by @Leechael
- Fix js test case. by @Leechael
- Fixed image url by @Leechael

### Removed
- Remove examples by @kvinwang
- Remove service namespace from the RPC by @kvinwang
- Remove /etc in compose file by @kvinwang

## New Contributors
* @HashWarlock made their first contribution
* @0xshawn made their first contribution
## [dev-v0.4.0.0] - 2025-01-17

### Added
- Add kms compose-dev.yaml by @kvinwang
- Add eventlog in KmsInfo by @kvinwang
- Add event digest validation in event logs replay by @kvinwang
- Add kms/README.md by @kvinwang
- Add transfer ownership to AppAuth.sol by @kvinwang
- Add demo cert in tappd by @kvinwang
- Add random seed for DeriveKey by @kvinwang
- Support for escape ansi color for docker logs by @kvinwang
- Add kms tapp by @kvinwang
- Add workaround for the network issue of the keyprovider by @kvinwang
- Add ci for next branch by @kvinwang
- Support for local key provider by @kvinwang
- Add key-provider build files by @kvinwang
- Add example of using prelaunch script by @kvinwang
- Add apparmor_restrict_unprivileged_userns troubleshooting. by @PierreLeGuen

### Changed
- Use intermediate cert to sign app certs by @kvinwang
- Merge remote-tracking branch 'master' into kms-onchain by @kvinwang
- Update kms/tapp/compose-dev.yaml by @kvinwang
- Rename mr_enclave to mr_aggregated by @kvinwang
- Update dependency versions by @kvinwang
- Validate kms cert by @kvinwang
- Fix cargo clippy by @kvinwang
- Update contract address by @kvinwang
- Add function to set quote and eventlog by @kvinwang
- Store bootstrap info on disk by @kvinwang
- Fix ts error in unittest by @kvinwang
- Show deploy tx hash by @kvinwang
- Update hardhat config by @kvinwang
- Add eventlog in bootstrap result by @kvinwang
- Default to 50 lines of log by @kvinwang
- Show tx hash by @kvinwang
- Better mrs display in the log by @kvinwang
- Fix response data schema by @kvinwang
- Hide Upgrade button for local instances by @kvinwang
- Add tasks by @kvinwang
- Use string as type of tproxyAppId by @kvinwang
- Auto apply certs from tappd by @kvinwang
- Add optional app_id set in UI by @kvinwang
- No default pccs_url by @kvinwang
- Add option tls_no_check_hostname by @kvinwang
- Better auto cert gen for kms & tproxy by @kvinwang
- Update typechain types by @kvinwang
- Update contract deployment script by @kvinwang
- Add api get_root_ca by @kvinwang
- Fix potential start failure by @kvinwang
- Update README.md by @kvinwang
- Update kms app compose by @kvinwang
- Update README by @kvinwang
- Cargo fmt by @kvinwang
- Layout adjustment for README by @kvinwang
- Fix cargo clippy and warnings by @kvinwang
- Remove a debug print by @kvinwang
- Print error log to console by @kvinwang
- Update .gitignore by @kvinwang
- Remove certs copying by @kvinwang
- Support for auto-bootstrap by @kvinwang
- Auto generate certs for dev by @kvinwang
- Fix cert issue in tproxy setup by @kvinwang
- Extract cert-client to seperate crate by @kvinwang
- Max cert chain len = 2 by @kvinwang
- Wip by @kvinwang
- Fix cert chain in derived key by @kvinwang
- Root-ca default filename by @kvinwang
- Write full certchain in cert by @kvinwang
- No short arg for certgen by @kvinwang
- Providing trusted tproxy id by @kvinwang
- Use mr-kp instead of kp-info to calc mr_enclave by @kvinwang
- Print key provider MR by @kvinwang
- Default kms port 8000 by @kvinwang
- Change default onboard port by @kvinwang
- Consistent appid by @kvinwang
- Optimize onboard UI by @kvinwang
- Fix 0x prefix when checking App authority by @kvinwang
- Better error report by @kvinwang
- Fix boot auth url path by @kvinwang
- Update kms config by @kvinwang
- Fix minor issues by @kvinwang
- Fix rootfs_hash parsing in tdxctl by @kvinwang
- Fix hardhat typechain error by @kvinwang
- Display compose hash by @kvinwang
- Kms contracts: Remove appController method by @kvinwang
- Refactor the contracts by @kvinwang
- Update kms Config by @kvinwang
- Tested by @kvinwang
- Auth-eth in ts by @kvinwang
- Add test for contract by @kvinwang
- Derive k256 keys by @kvinwang
- Onboard by @kvinwang
- Add more fields in AppInfo by @kvinwang
- Add ecdsa key provision by @kvinwang
- Support for webhook by @kvinwang
- Put rootfs_hash to kernel args by @kvinwang
- Update Cargo.lock by @kvinwang
- Merge remote-tracking branch 'ds/master' into next by @kvinwang
- Don't redirect stderr to /dev/null by @kvinwang
- Merge pull request #87 from Dstack-TEE/kp-compose by @kvinwang in [#87](https://github.com/Dstack-TEE/dstack/pull/87)
- Update .gitignore by @kvinwang
- Merge pull request #81 from Dstack-TEE/key-provider by @kvinwang in [#81](https://github.com/Dstack-TEE/dstack/pull/81)
- Add device-id in RTMR3 by @kvinwang
- KMS key provider takes precedence by @kvinwang
- Merge pull request #112 from AndrewMohawk/patch-1 by @kvinwang in [#112](https://github.com/Dstack-TEE/dstack/pull/112)
- Update README.md by @AndrewMohawk
- Merge pull request #105 from Dstack-TEE/prune-images by @kvinwang in [#105](https://github.com/Dstack-TEE/dstack/pull/105)
- Pruning unused images by @kvinwang
- Merge pull request #100 from Dstack-TEE/prelaunch-demo by @kvinwang in [#100](https://github.com/Dstack-TEE/dstack/pull/100)
- Merge pull request #106 from Dstack-TEE/fix-clippy by @kvinwang in [#106](https://github.com/Dstack-TEE/dstack/pull/106)
- Fix cargo clippy errors by @kvinwang
- Merge pull request #104 from Dstack-TEE/disk-req by @kvinwang in [#104](https://github.com/Dstack-TEE/dstack/pull/104)
- Add RAM and disk requirement by @kvinwang
- Update prerequisite dependencies by @nanometerzhu
- Merge pull request #95 from Dstack-TEE/remove-orphans by @kvinwang in [#95](https://github.com/Dstack-TEE/dstack/pull/95)
- Implement tdxctl remove-orphans by @kvinwang
- Merge pull request #94 from Dstack-TEE/pre_launch_script by @kvinwang in [#94](https://github.com/Dstack-TEE/dstack/pull/94)
- Add pre_launch_script in app-compose by @kvinwang
- Merge pull request #90 from PierreLeGuen/master by @kvinwang in [#90](https://github.com/Dstack-TEE/dstack/pull/90)

### Removed
- Remove mr ca-cert-hash by @kvinwang

## New Contributors
* @AndrewMohawk made their first contribution
* @PierreLeGuen made their first contribution
## [0.3.4] - 2025-01-04

### Changed
- Update Cargo.lock by @nanometerzhu
- Bump version to v0.3.4 by @nanometerzhu

## [0.3.4-beta] - 2025-01-02

### Changed
- No default not_before by @kvinwang
- Don't redirect stderr to /dev/null by @kvinwang
- Update .gitignore by @kvinwang
- Merge pull request #86 from Dstack-TEE/oom-protect by @kvinwang in [#86](https://github.com/Dstack-TEE/dstack/pull/86)
- Prevent tappd from be killed by OOM-killer by @kvinwang
- Merge pull request #85 from Dstack-TEE/fix-tproxy-conn by @Leechael in [#85](https://github.com/Dstack-TEE/dstack/pull/85)
- Fix bug in connection choosing by @kvinwang
- Merge pull request #84 from Dstack-TEE/readme by @h4x3rotab in [#84](https://github.com/Dstack-TEE/dstack/pull/84)
- Improve readme, address both code contrib and community by @h4x3rotab
- Fix a warning by @kvinwang
- Merge pull request #83 from Dstack-TEE/json-prpc by @kvinwang in [#83](https://github.com/Dstack-TEE/dstack/pull/83)
- Choose json codec in prpc clients by @kvinwang
- Move docker-daemon.json to meta repo by @kvinwang
- Merge pull request #82 from Dstack-TEE/safe-remove-orphans by @kvinwang in [#82](https://github.com/Dstack-TEE/dstack/pull/82)
- A better way to remove orphans by @kvinwang
- Merge pull request #46 from Dstack-TEE/feat-get-meta-api by @Leechael in [#46](https://github.com/Dstack-TEE/dstack/pull/46)
- Inspect public_logs and public_sysinfo option in Worker.Info by @Leechael
- Format by @Leechael
- Rename 'id' to 'instance_id' to avoid potential confusion by @Leechael
- Add GetMeta API for heartbeat. by @Leechael
- Add GetMeta API for heartbeat. by @Leechael
- Add GetMeta API for heartbeat. by @Leechael
- Merge pull request #80 from Dstack-TEE/tboot-no-shutdown by @kvinwang in [#80](https://github.com/Dstack-TEE/dstack/pull/80)
- Don't shutdown when tboot.sh fail by @kvinwang
- Merge pull request #79 from Dstack-TEE/remove-orphans by @kvinwang in [#79](https://github.com/Dstack-TEE/dstack/pull/79)
- Add --remove-orphans to docker compose up by @kvinwang
- Correct check for kmsEnabled in secrets reset by @kvinwang
- Merge pull request #78 from Dstack-TEE/wdg-tappd by @kvinwang in [#78](https://github.com/Dstack-TEE/dstack/pull/78)
- No hardcoded port for watchdog by @kvinwang
- Merge pull request #77 from Dstack-TEE/raw-quote by @kvinwang in [#77](https://github.com/Dstack-TEE/dstack/pull/77)
- Add standalone RawQuote API by @kvinwang
- Merge pull request #76 from Dstack-TEE/quote-prefix by @kvinwang in [#76](https://github.com/Dstack-TEE/dstack/pull/76)
- Add `prefix` for TdxQuote API by @kvinwang
- Merge pull request #74 from Dstack-TEE/confirm-rm by @kvinwang in [#74](https://github.com/Dstack-TEE/dstack/pull/74)
- Comfirm on removal by @kvinwang
- Merge pull request #75 from Dstack-TEE/git-ver by @kvinwang in [#75](https://github.com/Dstack-TEE/dstack/pull/75)
- Add git rev in Version rpc by @kvinwang
- Merge pull request #72 from Dstack-TEE/prpc-query-params by @kvinwang in [#72](https://github.com/Dstack-TEE/dstack/pull/72)
- Eliminates prpc routes file by @kvinwang
- Make the ra_rpc more easier to use by @kvinwang
- Support for reading args from url query by @kvinwang
- Merge pull request #73 from Dstack-TEE/e2fsck-no-reboot by @kvinwang in [#73](https://github.com/Dstack-TEE/dstack/pull/73)
- Don'nt reboot if the e2fsck corrected the fs errors by @kvinwang
- Better logs by @kvinwang
- Show compose file in tcb info by @kvinwang
- Display app name by @kvinwang
- Extract config loading logic to crate load_config by @kvinwang
- Add qmp sock by @kvinwang
- Better status display by @kvinwang

### Fixed
- Fix rev display by @kvinwang

## [0.3.3] - 2024-12-19

### Added
- Add service wg-checker by @kvinwang
- Support for upgrade image by @kvinwang
- Support for disk resizing by @kvinwang
- Add log config by @kvinwang
- Add default docker daemon config by @kvinwang
- Support for boot progress report by @kvinwang
- Add endpoint to ra-rpc server-side by @kvinwang
- Add crate http-client by @kvinwang
- Add crate host-api by @kvinwang
- Add rocket-vsock-listener by @kvinwang
- Add load file button to reset secret panel by @kvinwang

### Changed
- Make some codes more clear using cmd_lib by @kvinwang in [#71](https://github.com/Dstack-TEE/dstack/pull/71)
- Fix dev image does not upgrade by @kvinwang
- Remove since=1d from default logs url by @kvinwang
- Dstack v0.3.3 by @kvinwang in [#70](https://github.com/Dstack-TEE/dstack/pull/70)
- Merge pull request #69 from Dstack-TEE/kms-up by @kvinwang in [#69](https://github.com/Dstack-TEE/dstack/pull/69)
- Fix clippy by @kvinwang
- Allow upgrade base image by @kvinwang
- Fix first boot failure by @kvinwang
- Show version info on page by @kvinwang
- Fix error in console.html by @kvinwang
- Fix error removing .rootfs_hash in upgrading by @kvinwang
- Fix error in e2fsck by @kvinwang
- Fix error: missing bootstrapped when upgraded from old instance by @kvinwang
- Don't run docker compose pull by @kvinwang
- Merge pull request #68 from Dstack-TEE/wg-fix by @kvinwang in [#68](https://github.com/Dstack-TEE/dstack/pull/68)
- Set iptables to reject arbitray ip to send packets to wg port by @kvinwang
- Merge pull request #55 from Dstack-TEE/tappd-api by @kvinwang in [#55](https://github.com/Dstack-TEE/dstack/pull/55)
- Teepod & tappd: Default logs tail=20 by @kvinwang
- Handle app compose versioning by @kvinwang
- Support for optional logs/sysinfo API by @kvinwang
- Merge pull request #67 from Dstack-TEE/up-img by @kvinwang in [#67](https://github.com/Dstack-TEE/dstack/pull/67)
- Allow upgrade in 'exited' state by @kvinwang
- Sync dynamic config on start vm by @kvinwang
- Merge pull request #66 from Dstack-TEE/resize-disk by @kvinwang in [#66](https://github.com/Dstack-TEE/dstack/pull/66)
- Fix clippy by @kvinwang
- Turnneournald config by @kvinwang
- Web display by @kvinwang
- Only refress netinfo when running by @kvinwang
- Fix watchdog issue by @kvinwang
- Better status display by @kvinwang
- Merge pull request #64 from Dstack-TEE/tappd-wd by @kvinwang in [#64](https://github.com/Dstack-TEE/dstack/pull/64)
- Fix clippy by @kvinwang
- Add systemd watchdog by @kvinwang
- Merge pull request #65 from Dstack-TEE/docker-cfg by @kvinwang in [#65](https://github.com/Dstack-TEE/dstack/pull/65)
- Merge pull request #63 from Dstack-TEE/tappd-vsock by @kvinwang in [#63](https://github.com/Dstack-TEE/dstack/pull/63)
- Fix clippy by @kvinwang
- Adjust buttons layout by @kvinwang
- Reuse the same proto of guest api for teepod and tappd by @kvinwang
- Delegate tappd RPCs by @kvinwang
- Add guest api by @kvinwang
- Merge pull request #62 from Dstack-TEE/teepod-vsock by @kvinwang in [#62](https://github.com/Dstack-TEE/dstack/pull/62)
- Fix clippy by @kvinwang
- Accept boot progress report by @kvinwang
- Add client code in by @kvinwang
- Add prpc support by @kvinwang
- Impl host-api by @kvinwang
- Rename upgraded-app-id to compose-hash by @kvinwang
- Merge pull request #61 from Dstack-TEE/tproxy-url-rule by @kvinwang in [#61](https://github.com/Dstack-TEE/dstack/pull/61)
- The ending `s` in the url must be on the port part by @kvinwang
- Change logs since=1h to 0 by @kvinwang
- Merge pull request #60 from Dstack-TEE/tproxy-multi-connect by @kvinwang in [#60](https://github.com/Dstack-TEE/dstack/pull/60)
- Connect to multiple hosts by @kvinwang
- Fix clippy by @kvinwang
- Update prpc-build to 0.3.6 by @kvinwang
- Merge pull request #59 from Dstack-TEE/fix-app-id-on-reset by @kvinwang in [#59](https://github.com/Dstack-TEE/dstack/pull/59)
- Fix incorrect app-id on reset by @kvinwang
- Better logs filter by @kvinwang in [#58](https://github.com/Dstack-TEE/dstack/pull/58)
- Config for overall timeout for a connection by @kvinwang in [#57](https://github.com/Dstack-TEE/dstack/pull/57)
- Auto set ulimit -n by @kvinwang in [#56](https://github.com/Dstack-TEE/dstack/pull/56)
- Upgrade prpc-build to 0.3.5 by @kvinwang
- Upgrade to prpc-build 0.3.4 by @kvinwang
- Merge pull request #54 from Dstack-TEE/disable-scale-ext by @kvinwang in [#54](https://github.com/Dstack-TEE/dstack/pull/54)
- Disable scale ext for protos by @kvinwang
- Add load from file for secrets by @kvinwang
- Fix clippy by @kvinwang
- Merge pull request #52 from Dstack-TEE/vm-pty by @kvinwang in [#52](https://github.com/Dstack-TEE/dstack/pull/52)
- Open a pty for vm console by @kvinwang
- Merge pull request #51 from Dstack-TEE/cert-sign by @kvinwang in [#51](https://github.com/Dstack-TEE/dstack/pull/51)
- Add subcommand to sign a single cert by @kvinwang
- Use safe-write to store the state by @kvinwang
- Merge pull request #50 from Dstack-TEE/setup-wg by @kvinwang in [#50](https://github.com/Dstack-TEE/dstack/pull/50)
- Auto setup wg interface if not already by @kvinwang
- Merge pull request #49 from Dstack-TEE/fix-sdk-hint by @Leechael in [#49](https://github.com/Dstack-TEE/dstack/pull/49)
- Release js sdk 0.1.7 & python sdk 0.1.5 by @Leechael
- The length hint for raw report data in JS/TS SDK by @Leechael
- The length hint for raw report data in Python SDK by @Leechael
- Merge pull request #47 from Hyodar/feat/go-sdk by @kvinwang in [#47](https://github.com/Dstack-TEE/dstack/pull/47)
- Add package summary and author by @Hyodar
- Mention report data size and padding for raw hashing by @Hyodar
- Avoid unnecessary string operations by @Hyodar
- Add DeriveKeyWithSubject and DeriveKeyWithSubjectAndAltNames by @Hyodar
- Add TdxQuoteWithHashAlgorithm by @Hyodar
- Fix typo by @Hyodar
- Improve report data size check error on raw report by @Hyodar
- Add installation instructions and snippet by @Hyodar
- Add constructor options by @Hyodar
- Mention when altNames is included in the request by @Hyodar
- Avoid extra hex decoding in go SDK by @Hyodar
- Add logger to Tappd client creation in go SDK by @Hyodar
- Use info log instead of warn by @Hyodar
- Add RTMR replay to go SDK by @Hyodar
- Add hash algorithms support to go SDK by @Hyodar
- Add Go SDK README by @Hyodar
- Rename go package to tappd by @Hyodar
- Add Golang SDK by @Hyodar
- Simplify the syntax in Cargo.toml by @kvinwang
- Merge pull request #48 from Dstack-TEE/abspath by @kvinwang in [#48](https://github.com/Dstack-TEE/dstack/pull/48)
- Use path-absolutize instead of canonicalize by @kvinwang
- Merge pull request #45 from Dstack-TEE/sysinfo by @kvinwang in [#45](https://github.com/Dstack-TEE/dstack/pull/45)
- Fix cargo clippy by @kvinwang
- Add API SysInfo by @kvinwang

### Fixed
- Keep js sdk padding behavior consistent to python sdk by @Leechael
- Fix raw hashing test using SHA512 by @Hyodar
- Parse RTMRs manually and remove go-tdx-qpl dependency by @Hyodar
- Move tests to test package by @Hyodar
- Test parsing TDX quotes by @Hyodar
- Add go SDK unit tests by @Hyodar
- Add Go SDK unit tests by @Hyodar

## New Contributors
* @Hyodar made their first contribution
## [0.3.2] - 2024-12-09

### Added
- Add support for deriving an app instance by @kvinwang
- Add test case for reportdata check by @Leechael
- Add cargo test in action by @kvinwang
- Add github action clippy by @kvinwang
- Python SDK: add fn info() by @kvinwang
- Add killswitch contract by @kvinwang
- Add example crypt-kv by @kvinwang

### Changed
- V0.3.2 by @kvinwang in [#44](https://github.com/Dstack-TEE/dstack/pull/44)
- Merge pull request #43 from Dstack-TEE/custom-appid by @kvinwang in [#43](https://github.com/Dstack-TEE/dstack/pull/43)
- Cargo fmt by @kvinwang
- Teepod ui: Support for updating vcpu and memory by @kvinwang
- Support custom app-id by @kvinwang
- Validate the compose file when upgrading by @kvinwang
- Only list loadable images by @kvinwang
- Merge pull request #42 from Dstack-TEE/sdk-test-case-for-reportdata-verification by @Leechael in [#42](https://github.com/Dstack-TEE/dstack/pull/42)
- Fix clippy warnings for latest Rust by @kvinwang
- Fix tests by @kvinwang
- Cargo clippy by @kvinwang
- Cargo fmt by @kvinwang
- Format code by @kvinwang
- Merge pull request #41 from Dstack-TEE/cert-time by @kvinwang in [#41](https://github.com/Dstack-TEE/dstack/pull/41)
- Set the default certificate validity period to 1 year by @kvinwang
- Merge pull request #11 from Dstack-TEE/killswitch by @kvinwang in [#11](https://github.com/Dstack-TEE/dstack/pull/11)
- Update notebook by @kvinwang
- Add client code by @kvinwang
- Allow owner to ban self by @kvinwang
- Add info for internal RPC by @kvinwang
- Merge pull request #10 from Dstack-TEE/crypt-kv by @kvinwang in [#10](https://github.com/Dstack-TEE/dstack/pull/10)
- Add ipynb by @kvinwang
- Reduce directory level by @kvinwang

## [0.3.1] - 2024-12-05

### Added
- Add connect timeout & read first byte timeout for proxy by @Leechael
- Add hash_algorithm support python sdk by @Leechael
- Add VmMonitor.get_vm and VmInfo.to_pb by @Leechael
- Add Teepod.GetInfo & Teepod.ResizeVm by @Leechael
- Add TProxy.GetInfo by @Leechael
- Add supervisor by @kvinwang
- Add git rev to apps by @kvinwang
- Add cargo-check-all.sh by @kvinwang
- Support for docker login and registry mirror by @kvinwang
- Support for encrypted env vars by @kvinwang
- Add doc comment for tdxctl by @kvinwang
- Support for no KMS mode by @kvinwang
- Add tappd python client by @kvinwang
- Support for verify quote with PCCS by @kvinwang
- Add instance ID by @kvinwang
- Support to tls passthrough on common domain by @kvinwang
- Support for App Upgrade by @kvinwang
- Add contributors by @h4x3rotab
- Add troubleshooting by @h4x3rotab
- Add LICENSE by @kvinwang
- Support for dev version of image by @kvinwang
- Support for strip ansi colors by @kvinwang
- Add .cursorrules by @kvinwang
- Add certbot-cli by @kvinwang
- Add cert_bot and tests by @kvinwang
- Add Rust version ct_monitor by @kvinwang
- Add ct_monitor.py by @kvinwang
- Add certbot by @kvinwang
- Add user to libvirt group by @kvinwang
- Add external rpc for tappd by @kvinwang
- Add build script by @kvinwang
- Add list page for tproxy by @kvinwang
- Add --config for commands by @kvinwang
- Add vsock modules by @kvinwang
- Add missing cargo feature by @kvinwang
- Add test-scripts by @kvinwang
- Add tproxy by @kvinwang
- Add README.md by @kvinwang
- Support to install image by @kvinwang
- Add default config dir by @kvinwang
- Add teepod by @kvinwang
- Add tappd/tappd-rpc by @kvinwang
- Add mkguest by @kvinwang
- Add tdx-attest/tdxctl/iohash by @kvinwang
- Add tdx-attest-sys by @kvinwang
- Add kms-rpc,rarpc by @kvinwang
- Add kms by @kvinwang
- Add ratls by @kvinwang

### Changed
- Bump version to 0.3.1 by @kvinwang in [#39](https://github.com/Dstack-TEE/dstack/pull/39)
- Merge pull request #32 from Leechael/feat-tproxy-timeouts by @kvinwang in [#32](https://github.com/Dstack-TEE/dstack/pull/32)
- Fix jupyter notebook not work when the browser using a proxy network by @kvinwang
- More flex timeout config and other refactor by @kvinwang
- Merge pull request #38 from Dstack-TEE/universion by @kvinwang in [#38](https://github.com/Dstack-TEE/dstack/pull/38)
- Extract dependencies to workspace level by @kvinwang
- Use universe version for all Rust crates by @kvinwang
- Merge pull request #36 from Leechael/feat-sdk-and-quote by @kvinwang in [#36](https://github.com/Dstack-TEE/dstack/pull/36)
- Update js sdk by @Leechael
- Update python sdk by @Leechael
- Copy sdk codes from tappd-simulator by @Leechael
- Merge pull request #37 from Dstack-TEE/nanometerzhu-readme-mkisofs by @kvinwang in [#37](https://github.com/Dstack-TEE/dstack/pull/37)
- Mkisofs is also essential by @nanometerzhu
- Add app version header by @kvinwang
- Fix cid already in use by @kvinwang
- Merge pull request #33 from Leechael/feat-apis by @kvinwang in [#33](https://github.com/Dstack-TEE/dstack/pull/33)
- Merge remote-tracking branch 'origin/master' into mrg-master by @kvinwang
- Comment on the resize disk size behavior by @Leechael
- Merge pull request #35 from Dstack-TEE/raw-report-data by @kvinwang in [#35](https://github.com/Dstack-TEE/dstack/pull/35)
- Default to sha512 by @kvinwang
- Support for chosing hash for quote by @kvinwang
- Log by @kvinwang
- Use abspath for supervisor bin by @kvinwang
- Merge pull request #34 from Dstack-TEE/supervisor by @kvinwang in [#34](https://github.com/Dstack-TEE/dstack/pull/34)
- Rm comment by @kvinwang
- Update tests by @kvinwang
- Rename by @kvinwang
- Fix a deadlock by @kvinwang
- Fix the broken default log level by @kvinwang
- Extract process management to a standalone process by @kvinwang
- Add probe based client creation by @kvinwang
- Add client lib by @kvinwang
- Support for redirect log file by @kvinwang
- Expose some process structs by @kvinwang
- Support daemonize self and --pid-file by @kvinwang
- Add config and cmd args by @kvinwang
- Update rocket-apitoken by @kvinwang
- Merge pull request #31 from Dstack-TEE/teepod-auth by @kvinwang in [#31](https://github.com/Dstack-TEE/dstack/pull/31)
- Support for bearer auth by @kvinwang
- Fix Upgrade failure by @kvinwang
- Show qemu log in serial.log by @kvinwang
- Disable buffering for nginx by @kvinwang
- Extract cc-eventlog as a crate by @kvinwang
- Fix reboot issue for no-fde instance by @kvinwang
- Merge pull request #30 from Dstack-TEE/opt-fde by @kvinwang in [#30](https://github.com/Dstack-TEE/dstack/pull/30)
- Support for opt-out disck encryption by @kvinwang
- Merge pull request #29 from Dstack-TEE/docker-login by @kvinwang in [#29](https://github.com/Dstack-TEE/dstack/pull/29)
- Merge pull request #28 from Dstack-TEE/up-rustls by @kvinwang in [#28](https://github.com/Dstack-TEE/dstack/pull/28)
- Update rustls to 0.23.19 by @kvinwang
- Fix console crash if vm files are removed by @kvinwang
- No ca cert if kms is disabled by @kvinwang
- Custom event type by @kvinwang in [#27](https://github.com/Dstack-TEE/dstack/pull/27)
- Show event log in tappd dashboard by @kvinwang
- Define RTMR3 digest format by @kvinwang
- Update dcap-qvl to 0.1.6 by @kvinwang
- Prpc returns non Result by @kvinwang
- Better event log format by @kvinwang
- Merge pull request #26 from Dstack-TEE/tboot-rs by @kvinwang in [#26](https://github.com/Dstack-TEE/dstack/pull/26)
- Fix tproxy crash by @kvinwang
- Minor rename by @kvinwang
- Configurable dir for tboot by @kvinwang
- Use Rust client instead of curl by @kvinwang
- Update prpc to 0.3 by @kvinwang
- Fix qemu net args by @kvinwang
- Fix pubkey update issue after instance reboot by @kvinwang
- Cargo fmt by @kvinwang
- Merge pull request #25 from Dstack-TEE/tboot-rs by @kvinwang in [#25](https://github.com/Dstack-TEE/dstack/pull/25)
- Rewrite tboot.sh in Rust by @kvinwang
- Merge pull request #24 from Dstack-TEE/tproxy-update-pubkey by @kvinwang in [#24](https://github.com/Dstack-TEE/dstack/pull/24)
- Reject register without pubkey by @kvinwang
- Don't allocate new ip for rebooted instance by @kvinwang
- Merge pull request #23 from Dstack-TEE/tproxy-loadbalance by @kvinwang in [#23](https://github.com/Dstack-TEE/dstack/pull/23)
- Load balance by @kvinwang
- Merge pull request #22 from Dstack-TEE/tproxy-persistent by @kvinwang in [#22](https://github.com/Dstack-TEE/dstack/pull/22)
- Show latest handshake by @kvinwang
- Save/Load state by @kvinwang
- Merge pull request #21 from Dstack-TEE/recycle by @kvinwang in [#21](https://github.com/Dstack-TEE/dstack/pull/21)
- Recycle stale instances by @kvinwang
- Merge pull request #19 from Dstack-TEE/custom-net by @kvinwang in [#19](https://github.com/Dstack-TEE/dstack/pull/19)
- Support for custom netdev by @kvinwang
- Merge pull request #18 from Dstack-TEE/sec-env by @kvinwang in [#18](https://github.com/Dstack-TEE/dstack/pull/18)
- Derive for env encrypt key by @kvinwang
- Break on io error by @kvinwang
- Merge pull request #17 from Dstack-TEE/rm-build-sh by @kvinwang in [#17](https://github.com/Dstack-TEE/dstack/pull/17)
- Move build.sh to repo meta-dstack by @kvinwang
- Merge pull request #16 from Dstack-TEE/tailf by @kvinwang in [#16](https://github.com/Dstack-TEE/dstack/pull/16)
- Workaround for client disconnect issue for logs by @kvinwang
- Use tailf instead of linemux for log tailling by @kvinwang
- Move some basefiles from meta-dstack to this repo by @kvinwang
- Bump version to dstack-0.2.0 by @kvinwang
- Merge pull request #15 from Dstack-TEE/teepod-show-detail by @kvinwang in [#15](https://github.com/Dstack-TEE/dstack/pull/15)
- Show vm instance detail information by @kvinwang
- Merge pull request #14 from Dstack-TEE/no-kms by @kvinwang in [#14](https://github.com/Dstack-TEE/dstack/pull/14)
- Merge pull request #13 from Dstack-TEE/port_map by @kvinwang in [#13](https://github.com/Dstack-TEE/dstack/pull/13)
- Support for mapping host port to CVM by @kvinwang
- Merge pull request #12 from Dstack-TEE/rm-mkguest by @kvinwang in [#12](https://github.com/Dstack-TEE/dstack/pull/12)
- Fix compilation error by @kvinwang
- Merge pull request #9 from Dstack-TEE/py-tappd by @kvinwang in [#9](https://github.com/Dstack-TEE/dstack/pull/9)
- Support for setting alt names in derive_key by @kvinwang
- Add fn derive_key by @kvinwang
- Update README by @kvinwang
- Merge pull request #8 from Dstack-TEE/ccel by @kvinwang in [#8](https://github.com/Dstack-TEE/dstack/pull/8)
- Handle eventlogs by @kvinwang
- Support for parsing CCEL logs by @kvinwang
- Set default PCCS URL to PCS by @kvinwang
- Update dcap-qvl by @kvinwang
- Merge pull request #7 from Dstack-TEE/ratls-verify by @kvinwang in [#7](https://github.com/Dstack-TEE/dstack/pull/7)
- Add subcommand rand by @kvinwang
- Auto refresh by @kvinwang
- Merge pull request #6 from Dstack-TEE/instance-id by @kvinwang in [#6](https://github.com/Dstack-TEE/dstack/pull/6)
- Update README for address by instance id and passthrough by @kvinwang
- Use instance url instead of app url for dashboard by @kvinwang
- Merge pull request #5 from Dstack-TEE/passthrough by @kvinwang in [#5](https://github.com/Dstack-TEE/dstack/pull/5)
- Better base domain striping from SNI by @kvinwang
- Fix IPs in build.sh by @kvinwang
- Merge pull request #4 from Dstack-TEE/define-report-data by @kvinwang in [#4](https://github.com/Dstack-TEE/dstack/pull/4)
- Define quote report_data format and check the cert pubkey by @kvinwang
- Remove app id preview by @kvinwang
- Merge pull request #3 from Dstack-TEE/app-compose by @kvinwang in [#3](https://github.com/Dstack-TEE/dstack/pull/3)
- Switch to App compose format by @kvinwang
- Turn deploy into dialog by @kvinwang
- Check config by @kvinwang
- Better error message by @kvinwang
- Merge pull request #2 from Dstack-TEE/upgrade-app by @kvinwang in [#2](https://github.com/Dstack-TEE/dstack/pull/2)
- Support for App Upgrade by @kvinwang
- Store issued certs to fs by @kvinwang
- Merge pull request #1 from Dstack-TEE/contributors by @kvinwang in [#1](https://github.com/Dstack-TEE/dstack/pull/1)
- Update repo URL by @kvinwang
- Update README.md by @kvinwang
- Remove rproxy and implement our own by @kvinwang
- Fix md syntax by @kvinwang
- Update Cargo.lock by @kvinwang
- Update README.md by @kvinwang
- Fix utf8 decoding error in log by @kvinwang
- Default to show 1 hour logs by @kvinwang
- Implement TLS passthrough by @kvinwang
- Move deployed containers up by @kvinwang
- Optimiza tappd dashboard by @kvinwang
- Sort by create time by @kvinwang
- Support for start/remove by @kvinwang
- Support for reloading VMs by @kvinwang
- Modify manifest when stop vm by @kvinwang
- Use vm name and image name by @kvinwang
- Pretify console.html by @kvinwang
- Add link to tproxy by @kvinwang
- Support for bare log lines by @kvinwang
- Fix cvm log lines by @kvinwang
- Default to use dstack-0.1.0-dev by @kvinwang
- Add CID pool by @kvinwang
- Streaming API for CVM logs by @kvinwang
- Fix v9 mount name by @kvinwang
- Minor log fix by @kvinwang
- Add api to get Docker logs by @kvinwang
- Add subcommand add-caa by @kvinwang
- Don't add wg if exists by @kvinwang
- Better log by @kvinwang
- Soundness CAA setting by @kvinwang
- Support for adding CAA by @kvinwang
- Refine logs by @kvinwang
- Report error when CT log missing by @kvinwang
- CT log support for tproxy by @kvinwang
- Minor rename by @kvinwang
- Minor refactor by @kvinwang
- Use fs_err by @kvinwang
- Add auto renew feature by @kvinwang
- Add some doc comments by @kvinwang
- Adapt yocto by @kvinwang
- Make tdx-guest compatible with kernel 6.6 by @kvinwang
- Make mod tdx-guest compatible with yocto by @kvinwang
- Move tdx-guest src to root by @kvinwang
- Use syncconf instead of setconf by @kvinwang
- Use rinja for tproxy page by @kvinwang
- Use rinja instead of minijinja by @kvinwang
- Fix tests by @kvinwang
- Simplify the config file format by @kvinwang
- Minor rename by @kvinwang
- Mod default build config values by @kvinwang
- Minor HTML label change by @kvinwang
- Truncate rootfs hash to 64 by @kvinwang
- Better permission require in prepare_env.sh by @kvinwang
- Turn /tapp/config to /tapp by @kvinwang
- Show containers in Tappd by @kvinwang
- Fix invalid url by @kvinwang
- Fix incomplate build.sh by @kvinwang
- Fix empty attestation in CaCert by @kvinwang
- Enable ssh passwd login by @kvinwang
- Fix run scripts by @kvinwang
- Portmap for tproxy by @kvinwang
- Move the rpc crates into it's main crate by @kvinwang
- Use rproxy as a library by @kvinwang
- Change default config for kms by @kvinwang
- Teepod can run CVMs now by @kvinwang
- Add rpc List by @kvinwang
- Reconfig wg and proxy on startup by @kvinwang
- Truncate app id to 40 chars by @kvinwang
- Fix wg config issues by @kvinwang
- Optimize makefile by @kvinwang
- Fix a warning by @kvinwang
- Update ubuntu to 20240911 by @kvinwang
- Initramfs works now by @kvinwang
- Update kmfs by @kvinwang
- Update README.md by @kvinwang
- Refactor initrd by @kvinwang
- Create certgen by @kvinwang
- Implement derive key by @kvinwang
- Fix wg & rproxy config issues by @kvinwang
- Gen cert signed by ca file by @kvinwang
- Record empty app-id in MR by @kvinwang
- Fix panic in gen-ra-cert by @kvinwang
- Remvoe ifname from config by @kvinwang
- Use wg-quick to config wg interface by @kvinwang
- Exclude self-ip from the client pool by @kvinwang
- Add tests by @kvinwang
- Add EventLog by @kvinwang
- Better logs display by @kvinwang
- Fix mutlpile instance start failure by @kvinwang
- Fix initramfs hooks by @kvinwang
- Implement vm deployment by @kvinwang
- Port teepod to prpc by @kvinwang
- Add rpc TdxQuote by @kvinwang
- Implement rpc DeriveKey for tappd by @kvinwang
- Implement kdf for rcgen::KeyPair by @kvinwang
- Load app key by @kvinwang
- Use fs-err for better error message by @kvinwang
- Minor rename by @kvinwang
- Refactor kms-rpc file structure by @kvinwang
- Add --get-ra-cert by @kvinwang
- Implement RA RPC by @kvinwang
- Add Attestation extractor by @kvinwang

### Removed
- Remove a todo comment by @kvinwang
- Remove ubuntu-based image making by @kvinwang
- Remove app_info from cert by @kvinwang
- Remove deps on openssl by @kvinwang
- Remove the account_id workaround by @kvinwang
- Remove error in build.sh by @kvinwang
- Remove unused code by @kvinwang
- Remove certs dir by @kvinwang

## New Contributors
* @Leechael made their first contribution
* @nanometerzhu made their first contribution
* @h4x3rotab made their first contribution
[unreleased]: https://github.com/Dstack-TEE/dstack/compare/v0.5.3..HEAD
[0.5.3]: https://github.com/Dstack-TEE/dstack/compare/v0.5.2..v0.5.3
[0.5.2]: https://github.com/Dstack-TEE/dstack/compare/v0.5.1..v0.5.2
[0.5.1]: https://github.com/Dstack-TEE/dstack/compare/v0.5.0..v0.5.1
[0.5.0]: https://github.com/Dstack-TEE/dstack/compare/v0.4.2..v0.5.0
[0.4.2]: https://github.com/Dstack-TEE/dstack/compare/dev-v0.4.0.0..v0.4.2
[dev-v0.4.0.0]: https://github.com/Dstack-TEE/dstack/compare/v0.3.4..dev-v0.4.0.0
[0.3.4]: https://github.com/Dstack-TEE/dstack/compare/v0.3.4-beta..v0.3.4
[0.3.4-beta]: https://github.com/Dstack-TEE/dstack/compare/v0.3.3..v0.3.4-beta
[0.3.3]: https://github.com/Dstack-TEE/dstack/compare/v0.3.2..v0.3.3
[0.3.2]: https://github.com/Dstack-TEE/dstack/compare/v0.3.1..v0.3.2

<!-- generated by git-cliff -->
