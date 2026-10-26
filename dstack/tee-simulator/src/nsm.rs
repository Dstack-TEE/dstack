// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! CUSE implementation of the AWS Nitro Security Module ioctl ABI.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    mem,
    os::raw::{c_int, c_uint, c_void},
    path::Path,
    ptr,
    sync::{Arc, Mutex, OnceLock},
    thread,
    time::Duration,
};

use anyhow::{Context, Result};
use aws_nitro_enclaves_nsm_api::api::{Digest, ErrorCode, Request, Response};
use dstack_types::TeeSimulatorConfig;
use libc::{iovec, size_t};
use mock_attestation::{nsm::NsmGenerator, parse_seed};
use sha2::{Digest as _, Sha384};

static GENERATOR: OnceLock<Arc<NsmGenerator>> = OnceLock::new();
static STATE: OnceLock<Mutex<NsmState>> = OnceLock::new();
static CUSE: OnceLock<CuseApi> = OnceLock::new();

const PCR_COUNT: u16 = 32;
const PCR_SIZE: usize = 48;
const MAX_EXTEND_SIZE: usize = 1024;

struct NsmState {
    pcrs: Vec<[u8; PCR_SIZE]>,
    locked: BTreeSet<u16>,
}

impl Default for NsmState {
    fn default() -> Self {
        Self {
            pcrs: vec![[0; PCR_SIZE]; PCR_COUNT.into()],
            locked: BTreeSet::new(),
        }
    }
}

impl NsmState {
    fn measured() -> Self {
        let mut state = Self::default();
        for index in 0..=2 {
            let digest = Sha384::digest(format!("dstack-tee-simulator/nsm/pcr/{index}").as_bytes());
            state.pcrs[index].copy_from_slice(&digest);
        }
        state
    }

    fn handle(&mut self, generator: &NsmGenerator, request: Request) -> Response {
        match request {
            Request::DescribePCR { index } => {
                let Some(value) = self.pcrs.get(usize::from(index)) else {
                    return Response::Error(ErrorCode::InvalidIndex);
                };
                Response::DescribePCR {
                    lock: self.locked.contains(&index),
                    data: value.to_vec(),
                }
            }
            Request::ExtendPCR { index, data } => {
                if data.len() > MAX_EXTEND_SIZE {
                    return Response::Error(ErrorCode::InputTooLarge);
                }
                let Some(value) = self.pcrs.get_mut(usize::from(index)) else {
                    return Response::Error(ErrorCode::InvalidIndex);
                };
                if self.locked.contains(&index) {
                    return Response::Error(ErrorCode::ReadOnlyIndex);
                }
                let digest = Sha384::new()
                    .chain_update(value.as_slice())
                    .chain_update(data)
                    .finalize();
                value.copy_from_slice(&digest);
                Response::ExtendPCR {
                    data: value.to_vec(),
                }
            }
            Request::LockPCR { index } => {
                if index >= PCR_COUNT {
                    return Response::Error(ErrorCode::InvalidIndex);
                }
                self.locked.insert(index);
                Response::LockPCR
            }
            Request::LockPCRs { range } => {
                if range > PCR_COUNT {
                    return Response::Error(ErrorCode::InvalidIndex);
                }
                self.locked.extend(0..range);
                Response::LockPCRs
            }
            Request::DescribeNSM => Response::DescribeNSM {
                version_major: 1,
                version_minor: 0,
                version_patch: 0,
                module_id: "dstack-tee-simulator".into(),
                max_pcrs: PCR_COUNT,
                locked_pcrs: self.locked.clone(),
                digest: Digest::SHA384,
            },
            Request::Attestation {
                user_data,
                nonce,
                public_key,
            } => {
                let pcrs = self
                    .pcrs
                    .iter()
                    .enumerate()
                    .map(|(index, value)| (index as u16, value.to_vec()))
                    .collect::<BTreeMap<_, _>>();
                generator
                    .attest_with_claims(
                        user_data.as_ref().map(|value| value.as_slice()),
                        nonce.as_ref().map(|value| value.as_slice()),
                        public_key.as_ref().map(|value| value.as_slice()),
                        pcrs,
                    )
                    .map(|document| Response::Attestation { document })
                    .unwrap_or(Response::Error(ErrorCode::InternalError))
            }
            Request::GetRandom => Response::GetRandom {
                random: vec![0x42; 32],
            },
            _ => Response::Error(ErrorCode::InvalidOperation),
        }
    }
}

type FuseReq = *mut c_void;

#[repr(C)]
struct FuseFileInfo {
    _opaque: [u8; 0],
}

#[repr(C)]
struct CuseInfo {
    dev_major: c_uint,
    dev_minor: c_uint,
    dev_info_argc: c_uint,
    dev_info_argv: *mut *const libc::c_char,
    flags: c_uint,
}

#[repr(C)]
struct CuseOperations {
    init: *const c_void,
    init_done: Option<unsafe extern "C" fn(*mut c_void)>,
    destroy: *const c_void,
    open: Option<unsafe extern "C" fn(FuseReq, *mut FuseFileInfo)>,
    read: *const c_void,
    write: *const c_void,
    flush: *const c_void,
    release: Option<unsafe extern "C" fn(FuseReq, *mut FuseFileInfo)>,
    fsync: *const c_void,
    ioctl: Option<
        unsafe extern "C" fn(
            FuseReq,
            c_int,
            *mut c_void,
            *mut FuseFileInfo,
            c_uint,
            *const c_void,
            size_t,
            size_t,
        ),
    >,
    poll: *const c_void,
}

struct CuseApi {
    main: unsafe extern "C" fn(
        c_int,
        *mut *mut libc::c_char,
        *const CuseInfo,
        *const CuseOperations,
        *mut c_void,
    ) -> c_int,
    reply_open: unsafe extern "C" fn(FuseReq, *const FuseFileInfo) -> c_int,
    reply_err: unsafe extern "C" fn(FuseReq, c_int) -> c_int,
    reply_ioctl_retry:
        unsafe extern "C" fn(FuseReq, *const iovec, size_t, *const iovec, size_t) -> c_int,
    reply_ioctl: unsafe extern "C" fn(FuseReq, c_int, *const c_void, size_t) -> c_int,
}

fn cuse() -> &'static CuseApi {
    let Some(cuse) = CUSE.get() else {
        std::process::abort();
    };
    cuse
}

unsafe fn load_cuse() -> Result<CuseApi> {
    // FUSE 3.18 bumped the shared-library SONAME to 4. Keep the older SONAME
    // fallback so development binaries also run on distributions that still
    // ship the previous ABI.
    let library = libloading::Library::new("libfuse3.so.4")
        .or_else(|_| libloading::Library::new("libfuse3.so.3"))?;
    let library = Box::leak(Box::new(library));
    Ok(CuseApi {
        main: *library.get(b"cuse_lowlevel_main\0")?,
        reply_open: *library.get(b"fuse_reply_open\0")?,
        reply_err: *library.get(b"fuse_reply_err\0")?,
        reply_ioctl_retry: *library.get(b"fuse_reply_ioctl_retry\0")?,
        reply_ioctl: *library.get(b"fuse_reply_ioctl\0")?,
    })
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NsmMessage {
    request: iovec,
    response: iovec,
}

unsafe extern "C" fn open(req: FuseReq, fi: *mut FuseFileInfo) {
    (cuse().reply_open)(req, fi);
}

unsafe extern "C" fn release(req: FuseReq, _fi: *mut FuseFileInfo) {
    (cuse().reply_err)(req, 0);
}

unsafe extern "C" fn init_done(_userdata: *mut c_void) {
    if let Err(error) = ensure_nsm_device() {
        tracing::error!(?error, "failed to publish simulated NSM device");
        return;
    }
    if let Err(error) = sd_notify::notify(true, &[sd_notify::NotifyState::Ready]) {
        tracing::error!(?error, "failed to notify systemd that NSM is ready");
    }
}

fn ensure_nsm_device() -> Result<()> {
    let device_path = Path::new("/dev/nsm");
    let sysfs_paths = [
        Path::new("/sys/class/misc/nsm/dev"),
        Path::new("/sys/devices/virtual/misc/nsm/dev"),
    ];
    let mut stable_checks = 0;
    for _ in 0..100 {
        if device_path.exists() {
            stable_checks += 1;
            if stable_checks >= 10 {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(20));
            continue;
        }
        stable_checks = 0;
        if let Some(device) = sysfs_paths
            .iter()
            .find_map(|path| fs_err::read_to_string(path).ok())
        {
            let (major, minor) = device
                .trim()
                .split_once(':')
                .context("invalid NSM device number")?;
            let major = major.parse::<u32>().context("invalid NSM major number")?;
            let minor = minor.parse::<u32>().context("invalid NSM minor number")?;
            let path = CString::new("/dev/nsm")?;
            let result = unsafe {
                libc::mknod(
                    path.as_ptr(),
                    libc::S_IFCHR | 0o660,
                    libc::makedev(major, minor),
                )
            };
            if result == 0 || device_path.exists() {
                thread::sleep(Duration::from_millis(20));
                continue;
            }
            return Err(std::io::Error::last_os_error()).context("failed to create /dev/nsm");
        }
        thread::sleep(Duration::from_millis(20));
    }
    anyhow::bail!("CUSE NSM device did not appear in sysfs")
}

unsafe extern "C" fn ioctl(
    req: FuseReq,
    _cmd: c_int,
    arg: *mut c_void,
    _fi: *mut FuseFileInfo,
    _flags: c_uint,
    in_buf: *const c_void,
    in_bufsz: size_t,
    _out_bufsz: size_t,
) {
    let message_size = mem::size_of::<NsmMessage>();
    if in_bufsz == 0 {
        let message = iovec {
            iov_base: arg,
            iov_len: message_size,
        };
        (cuse().reply_ioctl_retry)(req, &message, 1, &message, 1);
        return;
    }
    if in_buf.is_null() || in_bufsz < message_size {
        (cuse().reply_err)(req, libc::EINVAL);
        return;
    }

    let message = ptr::read_unaligned(in_buf.cast::<NsmMessage>());
    if in_bufsz == message_size {
        if message.request.iov_len > 0x1000 || message.response.iov_len > 0x3000 {
            (cuse().reply_err)(req, libc::EMSGSIZE);
            return;
        }
        let input = [
            iovec {
                iov_base: arg,
                iov_len: message_size,
            },
            message.request,
        ];
        let output = [
            iovec {
                iov_base: arg,
                iov_len: message_size,
            },
            message.response,
        ];
        (cuse().reply_ioctl_retry)(req, input.as_ptr(), 2, output.as_ptr(), 2);
        return;
    }

    let request_bytes = std::slice::from_raw_parts(
        in_buf.cast::<u8>().add(message_size),
        in_bufsz - message_size,
    );
    let response = match serde_cbor::from_slice::<Request>(request_bytes) {
        Ok(request) => handle(request),
        Err(_) => Response::Error(ErrorCode::InvalidOperation),
    };
    let encoded = match serde_cbor::to_vec(&response) {
        Ok(encoded) if encoded.len() <= message.response.iov_len => encoded,
        _ => {
            (cuse().reply_err)(req, libc::EMSGSIZE);
            return;
        }
    };
    let mut updated = message;
    updated.response.iov_len = encoded.len();
    let mut output = Vec::with_capacity(message_size + encoded.len());
    output.extend_from_slice(std::slice::from_raw_parts(
        (&updated as *const NsmMessage).cast::<u8>(),
        message_size,
    ));
    output.extend_from_slice(&encoded);
    (cuse().reply_ioctl)(req, 0, output.as_ptr().cast(), output.len());
}

fn handle(request: Request) -> Response {
    let Some(generator) = GENERATOR.get() else {
        return Response::Error(ErrorCode::InternalError);
    };
    let Some(state) = STATE.get() else {
        return Response::Error(ErrorCode::InternalError);
    };
    state
        .lock()
        .map(|mut state| state.handle(generator, request))
        .unwrap_or(Response::Error(ErrorCode::InternalError))
}

pub fn run(config: &TeeSimulatorConfig) -> Result<()> {
    anyhow::ensure!(
        !std::path::Path::new("/dev/nsm").exists(),
        "refusing to replace a real NSM device"
    );
    CUSE.set(unsafe { load_cuse()? })
        .map_err(|_| anyhow::anyhow!("CUSE API was already initialized"))?;
    let seed = config
        .mock_attestation_seed
        .as_deref()
        .context("tee_simulator.mock_attestation_seed is required")?;
    GENERATOR
        .set(Arc::new(NsmGenerator::from_seed(parse_seed(seed)?)?))
        .map_err(|_| anyhow::anyhow!("NSM simulator was already initialized"))?;
    STATE
        .set(Mutex::new(NsmState::measured()))
        .map_err(|_| anyhow::anyhow!("NSM simulator state was already initialized"))?;

    let device_name = CString::new("DEVNAME=nsm")?;
    let mut device_args = [device_name.as_ptr(), ptr::null()];
    let info = CuseInfo {
        dev_major: 0,
        dev_minor: 0,
        dev_info_argc: 1,
        dev_info_argv: device_args.as_mut_ptr(),
        flags: 1, // CUSE_UNRESTRICTED_IOCTL
    };
    let operations = CuseOperations {
        init: ptr::null(),
        init_done: Some(init_done),
        destroy: ptr::null(),
        open: Some(open),
        read: ptr::null(),
        write: ptr::null(),
        flush: ptr::null(),
        release: Some(release),
        fsync: ptr::null(),
        ioctl: Some(ioctl),
        poll: ptr::null(),
    };
    let program = CString::new("dstack-tee-simulator")?;
    let foreground = CString::new("-f")?;
    let single_threaded = CString::new("-s")?;
    let mut argv = [
        program.as_ptr().cast_mut(),
        foreground.as_ptr().cast_mut(),
        single_threaded.as_ptr().cast_mut(),
    ];
    let result = unsafe {
        (cuse().main)(
            argv.len() as c_int,
            argv.as_mut_ptr(),
            &info,
            &operations,
            ptr::null_mut(),
        )
    };
    anyhow::ensure!(result == 0, "CUSE NSM session failed with status {result}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_nitro_enclaves_nsm_api::api::Request;

    fn response_kind(response: &Response) -> &'static str {
        match response {
            Response::DescribePCR { .. } => "DescribePCR",
            Response::ExtendPCR { .. } => "ExtendPCR",
            Response::LockPCR => "LockPCR",
            Response::LockPCRs => "LockPCRs",
            Response::DescribeNSM { .. } => "DescribeNSM",
            Response::Attestation { .. } => "Attestation",
            Response::GetRandom { .. } => "GetRandom",
            Response::Error(_) => "Error",
            _ => "Unknown",
        }
    }

    #[test]
    fn measured_state_models_a_production_enclave() {
        let state = NsmState::measured();
        assert!(state.pcrs[..=2]
            .iter()
            .all(|value| value.iter().any(|byte| *byte != 0)));
        assert!(state.pcrs[3..]
            .iter()
            .all(|value| value.iter().all(|byte| *byte == 0)));
    }

    #[test]
    fn pcr_lifecycle_matches_nsm_semantics() {
        let generator = NsmGenerator::from_seed([0x51; 32]).unwrap();
        let mut state = NsmState::default();
        match state.handle(&generator, Request::DescribePCR { index: 0 }) {
            Response::DescribePCR { lock, data } => {
                assert!(!lock);
                assert_eq!(data, vec![0; PCR_SIZE]);
            }
            response => panic!("unexpected {}", response_kind(&response)),
        }
        let input = b"measurement".to_vec();
        let expected = Sha384::new()
            .chain_update([0; PCR_SIZE])
            .chain_update(&input)
            .finalize()
            .to_vec();
        match state.handle(
            &generator,
            Request::ExtendPCR {
                index: 0,
                data: input,
            },
        ) {
            Response::ExtendPCR { data } => assert_eq!(data, expected),
            response => panic!("unexpected {}", response_kind(&response)),
        }
        assert!(matches!(
            state.handle(&generator, Request::LockPCR { index: 0 }),
            Response::LockPCR
        ));
        assert!(matches!(
            state.handle(
                &generator,
                Request::ExtendPCR {
                    index: 0,
                    data: vec![1],
                },
            ),
            Response::Error(ErrorCode::ReadOnlyIndex)
        ));
        assert!(matches!(
            state.handle(&generator, Request::DescribePCR { index: PCR_COUNT }),
            Response::Error(ErrorCode::InvalidIndex)
        ));
        assert!(matches!(
            state.handle(
                &generator,
                Request::ExtendPCR {
                    index: 1,
                    data: vec![0; MAX_EXTEND_SIZE + 1],
                },
            ),
            Response::Error(ErrorCode::InputTooLarge)
        ));
    }

    #[test]
    fn attestation_binds_claims_and_current_pcrs() {
        let generator = NsmGenerator::from_seed([0x52; 32]).unwrap();
        let verifier = nsm_qvl::QuoteVerifier::new(generator.root_ca_pem());
        let mut state = NsmState::default();
        assert!(matches!(
            state.handle(
                &generator,
                Request::ExtendPCR {
                    index: 2,
                    data: b"app".to_vec(),
                },
            ),
            Response::ExtendPCR { .. }
        ));
        let response = state.handle(
            &generator,
            Request::Attestation {
                user_data: Some(b"user".to_vec().into()),
                nonce: Some(b"nonce".to_vec().into()),
                public_key: Some(b"public".to_vec().into()),
            },
        );
        let Response::Attestation { document } = response else {
            panic!("unexpected {}", response_kind(&response));
        };
        let verified = verifier.verify(&document, None, None).unwrap();
        assert_eq!(verified.user_data.as_deref(), Some(b"user".as_slice()));
        assert_eq!(verified.nonce.as_deref(), Some(b"nonce".as_slice()));
        assert_eq!(verified.public_key.as_deref(), Some(b"public".as_slice()));
        assert_eq!(
            verified.pcrs.get(&2).map(Vec::as_slice),
            Some(state.pcrs[2].as_slice())
        );
    }
}
