// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! CUSE implementation of the AWS Nitro Security Module ioctl ABI.

use std::{
    ffi::CString,
    mem,
    os::raw::{c_int, c_uint, c_void},
    path::Path,
    ptr,
    sync::{Arc, OnceLock},
    thread,
    time::Duration,
};

use anyhow::{Context, Result};
use aws_nitro_enclaves_nsm_api::api::{Digest, ErrorCode, Request, Response};
use dstack_types::TeeSimulatorConfig;
use libc::{iovec, size_t};
use mock_attestation::{nsm::NsmGenerator, parse_seed};

static GENERATOR: OnceLock<Arc<NsmGenerator>> = OnceLock::new();
static CUSE: OnceLock<CuseApi> = OnceLock::new();

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
    match request {
        Request::Attestation { user_data, .. } => GENERATOR
            .get()
            .and_then(|generator| {
                let user_data = user_data
                    .as_ref()
                    .map(|data| data.as_slice())
                    .unwrap_or_default();
                generator.attest(user_data).ok()
            })
            .map(|document| Response::Attestation { document })
            .unwrap_or(Response::Error(ErrorCode::InternalError)),
        Request::DescribeNSM => Response::DescribeNSM {
            version_major: 1,
            version_minor: 0,
            version_patch: 0,
            module_id: "dstack-tee-simulator".into(),
            max_pcrs: 32,
            locked_pcrs: Default::default(),
            digest: Digest::SHA384,
        },
        Request::GetRandom => Response::GetRandom {
            random: vec![0x42; 32],
        },
        _ => Response::Error(ErrorCode::InvalidOperation),
    }
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
