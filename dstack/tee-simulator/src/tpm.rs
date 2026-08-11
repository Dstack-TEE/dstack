// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! swtpm-backed GCP vTPM environment, including the pre-provisioned AK
//! template and certificate NV indices consumed by `tpm-attest`.

use std::{
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{FileTypeExt as _, MetadataExt as _},
        unix::net::UnixStream,
    },
    path::Path,
    process::{Command, Stdio},
    thread,
    time::Duration,
};

use anyhow::{bail, Context, Result};
use aws_nitro_enclaves_nsm_api::api::{Request as NsmRequest, Response as NsmResponse};
use dstack_types::{AwsPcrReplay, TeeSimulatorConfig};
use mock_attestation::{nsm::NsmGenerator, parse_seed, server::MockCollateralState};
use tpm2::{add_command_capability, TpmAlgId, TpmCc, TpmContext};

const AK_ECC_CERT: &str = "0x01c10002";
const AK_ECC_TEMPLATE: &str = "0x01c10003";
const TPM2_CC_AWS_NSM_REQUEST: u32 = 0x2000_0001;
const VTPM_PROXY_IOC_NEW_DEV: libc::c_ulong = 0xc014_a100;
const VTPM_PROXY_FLAG_TPM2: u32 = 1;

#[repr(C)]
#[derive(Default)]
struct VtpmProxyNewDev {
    flags: u32,
    tpm_num: u32,
    fd: u32,
    major: u32,
    minor: u32,
}

struct NvWriteTemplate {
    request: Vec<u8>,
}

fn read_be_u16(bytes: &[u8], field: &str) -> Result<u16> {
    let bytes: [u8; 2] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid {field} length"))?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_be_u32(bytes: &[u8], field: &str) -> Result<u32> {
    let bytes: [u8; 4] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid {field} length"))?;
    Ok(u32::from_be_bytes(bytes))
}

fn command(program: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(program)
        .args(args)
        .env("TPM2TOOLS_TCTI", "device:/dev/tpm0")
        .status()
        .with_context(|| format!("failed to execute {program}"))?;
    if !status.success() {
        bail!("{program} failed with status {status}");
    }
    Ok(())
}

fn device_node_matches(path: &Path, major: u64, minor: u64) -> Result<bool> {
    let metadata = match fs_err::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    Ok(metadata.file_type().is_char_device()
        && nix::sys::stat::major(metadata.rdev()) == major
        && nix::sys::stat::minor(metadata.rdev()) == minor)
}

fn ensure_device_node(path: &Path, major: &str, minor: &str) -> Result<()> {
    let expected_major = major.parse().context("invalid device major")?;
    let expected_minor = minor.parse().context("invalid device minor")?;
    if device_node_matches(path, expected_major, expected_minor)? {
        return Ok(());
    }
    match fs_err::symlink_metadata(path) {
        Ok(_) => {
            // Recheck in case udev published the expected node between the two
            // metadata calls above.
            if device_node_matches(path, expected_major, expected_minor)? {
                return Ok(());
            }
            bail!(
                "{} exists but is not character device {expected_major}:{expected_minor}",
                path.display()
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let path_text = path.to_str().context("device path is not UTF-8")?;
    if let Err(error) = command("mknod", &[path_text, "c", major, minor]) {
        // udev can publish the node after the existence check but before
        // mknod. Accept only the exact character device registered by sysfs.
        if device_node_matches(path, expected_major, expected_minor)? {
            return Ok(());
        }
        return Err(error);
    }
    Ok(())
}

pub fn start_gcp_vtpm(runtime_dir: &Path, config: &TeeSimulatorConfig) -> Result<()> {
    if Path::new("/dev/tpmrm0").exists() || Path::new("/dev/tpm0").exists() {
        bail!("refusing to start the GCP vTPM simulator when a real TPM is present");
    }
    let seed = config
        .mock_attestation_seed
        .as_deref()
        .context("tee_simulator.mock_attestation_seed is required")?;
    let base_url = config
        .collateral_base_url
        .as_deref()
        .unwrap_or("http://127.0.0.1:8088");
    let state = MockCollateralState::from_seed(parse_seed(seed)?, base_url)?;
    // Keep swtpm state outside /run: swtpm drops privileges to `tss`, and some
    // distributions reject its lock file when a parent runtime directory is
    // owned by root even if the immediate state directory is writable.
    let state_dir = std::env::temp_dir().join(format!("dstack-swtpm-{}", std::process::id()));
    fs_err::create_dir_all(&state_dir)?;
    let state_arg = format!("dir={}", state_dir.display());
    let pid_file = std::env::temp_dir().join(format!("dstack-swtpm-{}.pid", std::process::id()));
    let pid_arg = format!("file={}", pid_file.display());
    command(
        "swtpm",
        &[
            "chardev",
            "--tpm2",
            "--tpmstate",
            &state_arg,
            "--vtpm-proxy",
            "--pid",
            &pid_arg,
            "--daemon",
        ],
    )?;
    fs_err::copy(&pid_file, runtime_dir.join("swtpm.pid"))?;

    for _ in 0..100 {
        create_tpm_device_node()?;
        if Path::new("/dev/tpmrm0").exists() || Path::new("/dev/tpm0").exists() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let mut startup_error = None;
    for _ in 0..100 {
        match command("tpm2_startup", &["-c"]) {
            Ok(()) => {
                startup_error = None;
                break;
            }
            Err(error) => {
                startup_error = Some(error);
                thread::sleep(Duration::from_millis(20));
            }
        }
    }
    if let Some(error) = startup_error {
        return Err(error).context("GCP vTPM did not become ready");
    }
    let replay = config
        .gcp_tpm_replay
        .as_ref()
        .context("tee_simulator.gcp_tpm_replay is required for GCP")?;
    validate_gcp_event_log(config, &replay.event_log)?;
    replay_gcp_event_log(&replay.event_log)?;
    install_gcp_event_log(&replay.event_log)?;

    let template_with_size = state_dir.join("ak.tpm2b-public");
    let generated_public = state_dir.join("ak.public");
    let template = state_dir.join("ak.template");
    let public_pem = state_dir.join("ak.pem");
    let context = state_dir.join("ak.ctx");
    command(
        "tpm2_createprimary",
        &[
            "-C",
            "e",
            "-G",
            "ecc256:ecdsa-sha256:null",
            "-g",
            "sha256",
            "-a",
            "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign|noda",
            "-c",
            context.to_str().context("invalid AK context path")?,
            "-o",
            generated_public
                .to_str()
                .context("invalid generated AK public path")?,
            "--template-data",
            template_with_size
                .to_str()
                .context("invalid AK public path")?,
        ],
    )?;
    command(
        "tpm2_readpublic",
        &[
            "-c",
            context.to_str().context("invalid AK context path")?,
            "-f",
            "pem",
            "-o",
            public_pem.to_str().context("invalid AK PEM path")?,
        ],
    )?;
    let bytes = fs_err::read(&template_with_size)?;
    anyhow::ensure!(!bytes.is_empty(), "invalid TPMT_PUBLIC generated by swtpm");
    fs_err::write(&template, bytes)?;

    let root_cert = state_dir.join("root.pem");
    let root_key = state_dir.join("root-key.pem");
    let ak_cert = state_dir.join("ak-cert.pem");
    let extensions = state_dir.join("ak-cert.ext");
    fs_err::write(&root_cert, state.tpm.root_ca_pem())?;
    fs_err::write(&root_key, state.tpm.root_key_pem())?;
    fs_err::write(
        &extensions,
        format!(
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nauthorityInfoAccess=caIssuers;URI:{base_url}/tpm/aia/root.pem\ncrlDistributionPoints=URI:{base_url}/tpm/crl/root.crl\n"
        ),
    )?;
    command(
        "openssl",
        &[
            "x509",
            "-new",
            "-force_pubkey",
            public_pem.to_str().context("invalid AK PEM path")?,
            "-CAkey",
            root_key.to_str().context("invalid root key path")?,
            "-CA",
            root_cert.to_str().context("invalid root cert path")?,
            "-CAcreateserial",
            "-days",
            "30",
            "-subj",
            "/CN=Mock GCP vTPM AK",
            "-extfile",
            extensions.to_str().context("invalid extension path")?,
            "-outform",
            "DER",
            "-out",
            ak_cert.to_str().context("invalid AK certificate path")?,
        ],
    )?;
    provision_nv(AK_ECC_TEMPLATE, &template)?;
    provision_nv(AK_ECC_CERT, &ak_cert)?;
    command("tpm2_flushcontext", &["-t"])?;
    Ok(())
}

fn validate_gcp_event_log(config: &TeeSimulatorConfig, mut bytes: &[u8]) -> Result<()> {
    let vm_config: dstack_types::VmConfig = serde_json::from_str(
        config
            .vm_config
            .as_deref()
            .context("tee_simulator.vm_config is required for GCP")?,
    )?;
    let expected = vm_config
        .gcp_measurement
        .as_ref()
        .context("vm_config.gcp_measurement is required for GCP")?
        .decode_measurement()
        .map_err(anyhow::Error::msg)?
        .uki_authenticode_sha256;
    let event_log = cc_eventlog::tpm::TpmEventLog::decode(&mut bytes)?;
    let actual = event_log
        .pcr2_events()
        .get(2)
        .context("GCP TPM event log is missing the UKI event")?
        .digest
        .clone();
    anyhow::ensure!(
        actual == expected,
        "GCP TPM event-log UKI digest does not match measurement.gcp.cbor"
    );
    Ok(())
}

fn replay_gcp_event_log(mut bytes: &[u8]) -> Result<()> {
    let event_log = cc_eventlog::tpm::TpmEventLog::decode(&mut bytes)?;
    for event in event_log.events {
        let extension = format!("{}:sha256={}", event.pcr_index, hex::encode(event.digest));
        command("tpm2_pcrextend", &[&extension])?;
    }
    Ok(())
}

fn install_gcp_event_log(bytes: &[u8]) -> Result<()> {
    let security_root = Path::new("/sys/kernel/security");
    let event_log = security_root.join("tpm0/binary_bios_measurements");
    if event_log.exists() {
        anyhow::ensure!(
            fs_err::read(&event_log)? == bytes,
            "existing simulated TPM event log does not match the image"
        );
        return Ok(());
    }
    let tpm_dir = event_log.parent().context("TPM event log has no parent")?;
    // securityfs does not permit userspace to create a synthetic TPM event
    // log hierarchy. Shadow it in this development-only guest before
    // publishing the event log that was replayed into the simulated PCRs.
    let flags = nix::mount::MsFlags::MS_NOSUID
        | nix::mount::MsFlags::MS_NODEV
        | nix::mount::MsFlags::MS_NOEXEC;
    nix::mount::mount(
        Some("dstack-tee-simulator"),
        security_root,
        Some("tmpfs"),
        flags,
        Some("mode=0755"),
    )
    .context("failed to mount simulated securityfs shadow")?;
    fs_err::create_dir_all(tpm_dir)
        .context("failed to create TPM event-log directory in securityfs shadow")?;
    fs_err::write(event_log, bytes).context("failed to install simulated TPM event log")
}
fn create_tpm_device_node() -> Result<()> {
    let sys_dev = Path::new("/sys/class/tpm/tpm0/dev");
    if !sys_dev.exists() {
        return Ok(());
    }
    let device = fs_err::read_to_string(sys_dev)?;
    let (major, minor) = device
        .trim()
        .split_once(':')
        .context("invalid /sys/class/tpm/tpm0/dev")?;
    ensure_device_node(Path::new("/dev/tpm0"), major, minor)
}

fn provision_nv(index: &str, contents: &Path) -> Result<()> {
    let size = fs_err::metadata(contents)?.len().to_string();
    command(
        "tpm2_nvdefine",
        &[index, "-C", "o", "-s", &size, "-a", "ownerread|ownerwrite"],
    )?;
    command(
        "tpm2_nvwrite",
        &[
            index,
            "-C",
            "o",
            "-i",
            contents.to_str().context("invalid NV input path")?,
        ],
    )
}

/// Run a TPM2 device backed by swtpm while implementing the NitroTPM NSM
/// vendor command at the TPM wire-protocol boundary. All ordinary commands,
/// including EK creation, HMAC sessions, and NV access, are handled by swtpm.
pub fn run_nitro_vtpm(runtime_dir: &Path, config: &TeeSimulatorConfig) -> Result<()> {
    if Path::new("/dev/tpmrm0").exists() || Path::new("/dev/tpm0").exists() {
        bail!("refusing to start the NitroTPM simulator when a real TPM is present");
    }
    let seed = config
        .mock_attestation_seed
        .as_deref()
        .context("tee_simulator.mock_attestation_seed is required")?;
    let generator = NsmGenerator::from_seed(parse_seed(seed)?)?;
    let (mut simulator, swtpm_stream) = UnixStream::pair()?;
    let swtpm_fd = swtpm_stream.as_raw_fd();
    let flags = nix::fcntl::FdFlag::from_bits_truncate(
        nix::fcntl::fcntl(swtpm_fd, nix::fcntl::FcntlArg::F_GETFD)
            .context("failed to get swtpm socket flags")?,
    );
    nix::fcntl::fcntl(
        swtpm_fd,
        nix::fcntl::FcntlArg::F_SETFD(flags - nix::fcntl::FdFlag::FD_CLOEXEC),
    )
    .context("failed to make swtpm socket inheritable")?;

    let state_dir = std::env::temp_dir().join(format!("dstack-nitro-swtpm-{}", std::process::id()));
    fs_err::create_dir_all(&state_dir)?;
    let state_arg = format!("dir={}", state_dir.display());
    let fd_arg = swtpm_fd.to_string();
    let mut child = Command::new("swtpm")
        .args([
            "chardev",
            "--tpm2",
            "--tpmstate",
            &state_arg,
            "--fd",
            &fd_arg,
            "--flags",
            "not-need-init,startup-clear",
            "--locality",
            "allow-set-locality",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .context("failed to start NitroTPM swtpm backend")?;
    drop(swtpm_stream);
    fs_err::write(runtime_dir.join("swtpm.pid"), child.id().to_string())?;

    let replay = config
        .aws_pcr_replay
        .as_ref()
        .context("tee_simulator.aws_pcr_replay is required for NitroTPM")?;
    replay_aws_boot_pcrs(&mut simulator, replay)?;

    let (control, mut proxy, tpm_num) = create_vtpm_proxy()?;
    let proxy_thread = thread::spawn(move || {
        let _control = control;
        let result = proxy_tpm_commands(&mut proxy, &mut simulator, &generator);
        if let Err(error) = &result {
            tracing::error!(?error, "NitroTPM proxy failed");
        }
        result
    });
    let sys_dev = format!("/sys/class/tpm/tpm{tpm_num}/dev");
    for _ in 0..100 {
        if Path::new(&sys_dev).exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let device = fs_err::read_to_string(&sys_dev).context("vTPM was not registered")?;
    let (major, minor) = device
        .trim()
        .split_once(':')
        .context("invalid vTPM device number")?;
    ensure_device_node(Path::new("/dev/tpm0"), major, minor)?;
    sd_notify::notify(true, &[sd_notify::NotifyState::Ready])?;
    let result = proxy_thread
        .join()
        .map_err(|_| anyhow::anyhow!("NitroTPM proxy thread panicked"))?;
    let _ = child.kill();
    result
}

fn replay_aws_boot_pcrs(backend: &mut UnixStream, replay: &AwsPcrReplay) -> Result<()> {
    anyhow::ensure!(replay.version == 1, "unsupported AWS PCR replay version");
    let mut tpm = TpmContext::from_stream(
        backend
            .try_clone()
            .context("failed to clone NitroTPM stream for PCR replay")?,
        "NitroTPM replay backend",
    );
    for event in &replay.events {
        anyhow::ensure!(
            matches!(event.pcr, 4 | 7 | 12),
            "AWS PCR replay contains unsupported PCR {}",
            event.pcr
        );
        anyhow::ensure!(
            event.digest.len() == 48,
            "AWS PCR replay event digest must be SHA-384"
        );
        tpm.pcr_extend(event.pcr.into(), &event.digest, TpmAlgId::Sha384)
            .with_context(|| {
                format!(
                    "failed to replay {} into PCR{}",
                    event.event_type, event.pcr
                )
            })?;
    }
    for (index, expected) in [(4u16, &replay.pcr4), (7, &replay.pcr7), (12, &replay.pcr12)] {
        anyhow::ensure!(expected.len() == 48, "expected PCR{index} must be SHA-384");
        let actual = tpm.pcr_read_single(index.into(), TpmAlgId::Sha384)?;
        anyhow::ensure!(
            actual == *expected,
            "replayed PCR{index} mismatch: expected={}, actual={}",
            hex::encode(expected),
            hex::encode(actual)
        );
    }
    Ok(())
}

fn create_vtpm_proxy() -> Result<(std::fs::File, std::fs::File, u32)> {
    let control = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/vtpmx")
        .context("failed to open /dev/vtpmx; load tpm_vtpm_proxy")?;
    let mut new_dev = VtpmProxyNewDev {
        flags: VTPM_PROXY_FLAG_TPM2,
        ..Default::default()
    };
    let rc = unsafe { libc::ioctl(control.as_raw_fd(), VTPM_PROXY_IOC_NEW_DEV, &mut new_dev) };
    anyhow::ensure!(
        rc == 0,
        "failed to create vTPM proxy device: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: the successful ioctl returned ownership of this new descriptor.
    Ok((
        control,
        unsafe { std::fs::File::from_raw_fd(new_dev.fd as i32) },
        new_dev.tpm_num,
    ))
}

fn proxy_tpm_commands(
    proxy: &mut std::fs::File,
    backend: &mut UnixStream,
    generator: &NsmGenerator,
) -> Result<()> {
    let mut nv_write = None;
    let mut nsm_response = None;
    loop {
        let mut command = vec![0u8; 65_536];
        let size = loop {
            match proxy.read(&mut command) {
                Ok(size) => break size,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) if error.raw_os_error() == Some(libc::EPIPE) => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error).context("failed to read vTPM command"),
            }
        };
        if size == 0 {
            return Ok(());
        }
        command.truncate(size);
        anyhow::ensure!(command.len() >= 10, "truncated TPM command");
        let code = read_be_u32(&command[6..10], "TPM command code")?;
        let response = if code == TPM2_CC_AWS_NSM_REQUEST {
            let template = nv_write
                .as_ref()
                .context("NitroTPM vendor command without an NV request")?;
            nsm_response = Some(handle_nsm_vendor_command(generator, template, backend)?);
            tpm_success_response()
        } else if code == TpmCc::NvRead.to_u32() && nsm_response.is_some() {
            nv_read_response(
                &command,
                nsm_response.as_deref().context("missing NSM response")?,
            )?
        } else if code == TpmCc::NvReadPublic.to_u32() && nsm_response.is_some() {
            let mut response = transact(backend, &command)?;
            set_nv_public_size(
                &mut response,
                nsm_response
                    .as_deref()
                    .context("missing NSM response")?
                    .len(),
            )?;
            response
        } else {
            // NitroTPM permits an 8 KiB message NV space while libtpms caps a
            // single NV index at 2 KiB. Define the backing index at that limit;
            // the proxy virtualizes its public size and reads after the vendor
            // command, while swtpm still handles its lifecycle and auth setup.
            if code == TpmCc::NvDefineSpace.to_u32() && command.ends_with(&8192u16.to_be_bytes()) {
                let end = command.len();
                command[end - 2..].copy_from_slice(&2048u16.to_be_bytes());
            }
            if code == TpmCc::NvWrite.to_u32() {
                if let Some(template) = parse_nv_write(&command)? {
                    nv_write = Some(template);
                }
            }
            let mut response = transact(backend, &command)?;
            advertise_nsm_vendor_command(code, &mut response)?;
            response
        };
        proxy
            .write_all(&response)
            .context("failed to write vTPM response")?;
    }
}

fn advertise_nsm_vendor_command(code: u32, response: &mut Vec<u8>) -> Result<()> {
    if code == TpmCc::GetCapability.to_u32() {
        *response = add_command_capability(response, TPM2_CC_AWS_NSM_REQUEST)?;
    }
    Ok(())
}

fn parse_nv_write(command: &[u8]) -> Result<Option<NvWriteTemplate>> {
    // sessions header + auth handle + NV index + authorizationSize
    if command.len() < 24 {
        return Ok(None);
    }
    let index = read_be_u32(&command[14..18], "NV index")?;
    if !(0x0100_0000..=0x01ff_ffff).contains(&index) {
        return Ok(None);
    }
    let auth_size = read_be_u32(&command[18..22], "NV authorization size")? as usize;
    let data_size_pos = 22usize
        .checked_add(auth_size)
        .context("NV write size overflow")?;
    anyhow::ensure!(command.len() >= data_size_pos + 4, "truncated NV write");
    let data_size = read_be_u16(
        &command[data_size_pos..data_size_pos + 2],
        "NV write data size",
    )? as usize;
    let data_start = data_size_pos + 2;
    let data_end = data_start + data_size;
    anyhow::ensure!(command.len() >= data_end + 2, "truncated NV write data");
    let request = command[data_start..data_end].to_vec();
    Ok(Some(NvWriteTemplate { request }))
}

fn handle_nsm_vendor_command(
    generator: &NsmGenerator,
    template: &NvWriteTemplate,
    backend: &mut UnixStream,
) -> Result<Vec<u8>> {
    let request: NsmRequest = serde_cbor::from_slice(&template.request)?;
    let response = match request {
        NsmRequest::Attestation { user_data, .. } => {
            let mut tpm = TpmContext::from_stream(
                backend
                    .try_clone()
                    .context("failed to clone NitroTPM stream")?,
                "NitroTPM backend",
            );
            let pcrs = [4u16, 7, 8, 12, 14]
                .into_iter()
                .map(|index| Ok((index, tpm.pcr_read_single(index.into(), TpmAlgId::Sha384)?)))
                .collect::<Result<_>>()?;
            let document = generator.attest_with_pcrs(
                user_data.as_ref().map(|v| v.as_slice()).unwrap_or_default(),
                pcrs,
            )?;
            NsmResponse::Attestation { document }
        }
        _ => anyhow::bail!("unsupported NitroTPM NSM request"),
    };
    Ok(serde_cbor::to_vec(&response)?)
}

fn set_nv_public_size(response: &mut [u8], size: usize) -> Result<()> {
    anyhow::ensure!(response.len() >= 26, "truncated NV_ReadPublic response");
    let policy_size_pos = 22;
    let policy_size = read_be_u16(
        &response[policy_size_pos..policy_size_pos + 2],
        "NV policy size",
    )? as usize;
    let data_size_pos = policy_size_pos + 2 + policy_size;
    anyhow::ensure!(
        response.len() >= data_size_pos + 2,
        "truncated NV public area"
    );
    response[data_size_pos..data_size_pos + 2].copy_from_slice(&(size as u16).to_be_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gcp_event_log_is_bound_to_vm_measurement() {
        let fixture = include_bytes!("../../cc-eventlog/samples/tpm_eventlog.bin");
        let fixture_hash =
            hex::decode("9ab14a46f858662a89adc102d2a57a13f52f75c1769d65a4c34edbbfc8855f0f")
                .unwrap();
        let image_hash = vec![0x5a; 32];
        let offset = fixture
            .windows(fixture_hash.len())
            .position(|window| window == fixture_hash)
            .unwrap();
        let mut event_log = fixture.to_vec();
        event_log[offset..offset + image_hash.len()].copy_from_slice(&image_hash);

        let measurement = dstack_types::GcpOsImageMeasurement::new(image_hash).unwrap();
        let document =
            dstack_types::GcpOsImageMeasurementDocument::from_measurement(Vec::new(), measurement);
        let mut config = TeeSimulatorConfig {
            vm_config: Some(serde_json::json!({ "gcp_measurement": document }).to_string()),
            ..Default::default()
        };
        validate_gcp_event_log(&config, &event_log).unwrap();

        config.vm_config = Some("{}".into());
        assert!(validate_gcp_event_log(&config, &event_log).is_err());
    }
}

fn nv_read_response(command: &[u8], contents: &[u8]) -> Result<Vec<u8>> {
    anyhow::ensure!(command.len() >= 4, "truncated NV_Read command");
    let size = read_be_u16(
        &command[command.len() - 4..command.len() - 2],
        "NV read size",
    )? as usize;
    let offset = read_be_u16(&command[command.len() - 2..], "NV read offset")? as usize;
    let end = (offset + size).min(contents.len());
    anyhow::ensure!(offset <= end, "invalid NV_Read offset");
    let data = &contents[offset..end];
    let parameter_size = 2 + data.len();
    let total_size = 10 + 4 + parameter_size + 5;
    let mut response = Vec::with_capacity(total_size);
    response.extend_from_slice(&0x8002u16.to_be_bytes());
    response.extend_from_slice(&(total_size as u32).to_be_bytes());
    response.extend_from_slice(&0u32.to_be_bytes());
    response.extend_from_slice(&(parameter_size as u32).to_be_bytes());
    response.extend_from_slice(&(data.len() as u16).to_be_bytes());
    response.extend_from_slice(data);
    response.extend_from_slice(&[0, 0, 0, 0, 0]);
    Ok(response)
}

fn transact(stream: &mut UnixStream, command: &[u8]) -> Result<Vec<u8>> {
    stream.write_all(command)?;
    let mut header = [0u8; 10];
    stream.read_exact(&mut header)?;
    let size = read_be_u32(&header[2..6], "TPM response size")? as usize;
    anyhow::ensure!(size >= header.len(), "invalid TPM response size");
    let mut response = Vec::with_capacity(size);
    response.extend_from_slice(&header);
    response.resize(size, 0);
    stream.read_exact(&mut response[10..])?;
    Ok(response)
}

fn tpm_success_response() -> Vec<u8> {
    [0x80, 0x01, 0, 0, 0, 10, 0, 0, 0, 0].to_vec()
}
