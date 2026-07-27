// dstack patch: vendored third-party code is carried to be patched as little as
// possible, not rewritten to this workspace's lint policy. A path dependency is
// a local package, so cargo does not cap its lints the way it would for a
// crates.io one, and CI's `-D clippy::expect_used -D clippy::unwrap_used` would
// otherwise fail on upstream code unrelated to the musl fix. Attribute levels
// beat command-line ones, which a `[lints]` table in Cargo.toml does not.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use ffi::{setup_tls_info, setup_ulp, KtlsCompatibilityError};
use futures_util::future::try_join_all;
use ktls_sys::bindings as sys;
use rustls::{Connection, SupportedCipherSuite, SupportedProtocolVersion};

#[cfg(all(not(feature = "ring"), not(feature = "aws_lc_rs")))]
compile_error!("This crate needs wither the 'ring' or 'aws_lc_rs' feature enabled");
#[cfg(all(feature = "ring", feature = "aws_lc_rs"))]
compile_error!("The 'ring' and 'aws_lc_rs' features are mutually exclusive");
#[cfg(feature = "aws_lc_rs")]
use rustls::crypto::aws_lc_rs::cipher_suite;
#[cfg(feature = "ring")]
use rustls::crypto::ring::cipher_suite;

use smallvec::SmallVec;
use std::{
    future::Future,
    io,
    net::SocketAddr,
    os::unix::prelude::{AsRawFd, RawFd},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite},
    net::{TcpListener, TcpStream},
};

mod ffi;
pub use crate::ffi::CryptoInfo;

mod async_read_ready;
pub use async_read_ready::AsyncReadReady;

mod ktls_stream;
pub use ktls_stream::KtlsStream;

mod cork_stream;
pub use cork_stream::CorkStream;

#[derive(Debug, Default)]
pub struct CompatibleCiphers {
    pub tls12: CompatibleCiphersForVersion,
    pub tls13: CompatibleCiphersForVersion,
}

#[derive(Debug, Default)]
pub struct CompatibleCiphersForVersion {
    pub aes_gcm_128: bool,
    pub aes_gcm_256: bool,
    pub chacha20_poly1305: bool,
}

impl CompatibleCiphers {
    /// List compatible ciphers. This listens on a TCP socket and blocks for a
    /// little while. Do once at the very start of a program. Should probably be
    /// behind a lazy_static / once_cell
    pub async fn new() -> io::Result<Self> {
        let mut ciphers = CompatibleCiphers::default();

        let ln = TcpListener::bind("0.0.0.0:0").await?;
        let local_addr = ln.local_addr()?;

        // Accepted conns of ln
        let mut accepted_conns: SmallVec<[TcpStream; 12]> = SmallVec::new();

        let accept_conns_fut = async {
            loop {
                if let Ok((conn, _addr)) = ln.accept().await {
                    accepted_conns.push(conn);
                }
            }
        };

        ciphers.test_ciphers(local_addr, accept_conns_fut).await?;

        Ok(ciphers)
    }

    async fn test_ciphers(
        &mut self,
        local_addr: SocketAddr,
        accept_conns_fut: impl Future<Output = ()>,
    ) -> io::Result<()> {
        let ciphers: Vec<(SupportedCipherSuite, &mut bool)> = vec![
            (
                cipher_suite::TLS13_AES_128_GCM_SHA256,
                &mut self.tls13.aes_gcm_128,
            ),
            (
                cipher_suite::TLS13_AES_256_GCM_SHA384,
                &mut self.tls13.aes_gcm_256,
            ),
            (
                cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
                &mut self.tls13.chacha20_poly1305,
            ),
            (
                cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                &mut self.tls12.aes_gcm_128,
            ),
            (
                cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                &mut self.tls12.aes_gcm_256,
            ),
            (
                cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                &mut self.tls12.chacha20_poly1305,
            ),
        ];

        let create_connections_fut =
            try_join_all((0..ciphers.len()).map(|_| TcpStream::connect(local_addr)));

        let socks = tokio::select! {
            // Use biased here to optimize performance.
            //
            // With biased, tokio::select! would first poll create_connections_fut,
            // which would poll all `TcpStream::connect` futures and requests
            // new connections to `ln` then returns `Poll::Pending`.
            //
            // Then accept_conns_fut would be polled, which accepts all pending
            // connections, wake up create_connections_fut then returns
            // `Poll::Pending`.
            //
            // Finally, create_connections_fut wakes up and all connections
            // are ready, the result is collected into a Vec and ends
            // the tokio::select!.
            biased;

            res = create_connections_fut => res?,
            _ = accept_conns_fut => unreachable!(),
        };

        assert_eq!(ciphers.len(), socks.len());

        ciphers
            .into_iter()
            .zip(socks)
            .for_each(|((cipher_suite, field), sock)| {
                *field = sample_cipher_setup(&sock, cipher_suite).is_ok();
            });

        Ok(())
    }

    /// Returns true if we're reasonably confident that functions like
    /// [config_ktls_client] and [config_ktls_server] will succeed.
    pub fn is_compatible(&self, suite: SupportedCipherSuite) -> bool {
        let kcs = match KtlsCipherSuite::try_from(suite) {
            Ok(kcs) => kcs,
            Err(_) => return false,
        };

        let fields = match kcs.version {
            KtlsVersion::TLS12 => &self.tls12,
            KtlsVersion::TLS13 => &self.tls13,
        };

        match kcs.typ {
            KtlsCipherType::AesGcm128 => fields.aes_gcm_128,
            KtlsCipherType::AesGcm256 => fields.aes_gcm_256,
            KtlsCipherType::Chacha20Poly1305 => fields.chacha20_poly1305,
        }
    }
}

fn sample_cipher_setup(sock: &TcpStream, cipher_suite: SupportedCipherSuite) -> Result<(), Error> {
    let kcs = match KtlsCipherSuite::try_from(cipher_suite) {
        Ok(kcs) => kcs,
        Err(_) => panic!("unsupported cipher suite"),
    };

    let ffi_version = match kcs.version {
        KtlsVersion::TLS12 => ffi::TLS_1_2_VERSION_NUMBER,
        KtlsVersion::TLS13 => ffi::TLS_1_3_VERSION_NUMBER,
    };

    let crypto_info = match kcs.typ {
        KtlsCipherType::AesGcm128 => CryptoInfo::AesGcm128(sys::tls12_crypto_info_aes_gcm_128 {
            info: sys::tls_crypto_info {
                version: ffi_version,
                cipher_type: sys::TLS_CIPHER_AES_GCM_128 as _,
            },
            iv: Default::default(),
            key: Default::default(),
            salt: Default::default(),
            rec_seq: Default::default(),
        }),
        KtlsCipherType::AesGcm256 => CryptoInfo::AesGcm256(sys::tls12_crypto_info_aes_gcm_256 {
            info: sys::tls_crypto_info {
                version: ffi_version,
                cipher_type: sys::TLS_CIPHER_AES_GCM_256 as _,
            },
            iv: Default::default(),
            key: Default::default(),
            salt: Default::default(),
            rec_seq: Default::default(),
        }),
        KtlsCipherType::Chacha20Poly1305 => {
            CryptoInfo::Chacha20Poly1305(sys::tls12_crypto_info_chacha20_poly1305 {
                info: sys::tls_crypto_info {
                    version: ffi_version,
                    cipher_type: sys::TLS_CIPHER_CHACHA20_POLY1305 as _,
                },
                iv: Default::default(),
                key: Default::default(),
                salt: Default::default(),
                rec_seq: Default::default(),
            })
        }
    };
    let fd = sock.as_raw_fd();

    setup_ulp(fd).map_err(Error::UlpError)?;

    setup_tls_info(fd, ffi::Direction::Tx, crypto_info)?;

    Ok(())
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to enable TLS ULP (upper level protocol): {0}")]
    UlpError(#[source] std::io::Error),

    #[error("kTLS compatibility error: {0}")]
    KtlsCompatibility(#[from] KtlsCompatibilityError),

    #[error("failed to export secrets")]
    ExportSecrets(#[source] rustls::Error),

    #[error("failed to configure tx/rx (unsupported cipher?): {0}")]
    TlsCryptoInfoError(#[source] std::io::Error),

    #[error("an I/O occured while draining the rustls stream: {0}")]
    DrainError(#[source] std::io::Error),

    #[error("no negotiated cipher suite: call config_ktls_* only /after/ the handshake")]
    NoNegotiatedCipherSuite,
}

/// Configure kTLS for this socket. If this call succeeds, data can be written
/// and read from this socket, and the kernel takes care of encryption
/// transparently. I'm not clear how rekeying is handled (probably via control
/// messages, but can't find a code sample for it).
///
/// The inner IO type must be wrapped in [CorkStream] since it's the only way
/// to drain a rustls stream cleanly. See its documentation for details.
pub async fn config_ktls_server<IO>(
    mut stream: tokio_rustls::server::TlsStream<CorkStream<IO>>,
) -> Result<KtlsStream<IO>, Error>
where
    IO: AsRawFd + AsyncRead + AsyncReadReady + AsyncWrite + Unpin,
{
    stream.get_mut().0.corked = true;
    let drained = drain(&mut stream).await.map_err(Error::DrainError)?;
    let (io, conn) = stream.into_inner();
    let io = io.io;

    setup_inner(io.as_raw_fd(), Connection::Server(conn))?;
    Ok(KtlsStream::new(io, drained))
}

/// Configure kTLS for this socket. If this call succeeds, data can be
/// written and read from this socket, and the kernel takes care of encryption
/// (and key updates, etc.) transparently.
///
/// The inner IO type must be wrapped in [CorkStream] since it's the only way
/// to drain a rustls stream cleanly. See its documentation for details.
pub async fn config_ktls_client<IO>(
    mut stream: tokio_rustls::client::TlsStream<CorkStream<IO>>,
) -> Result<KtlsStream<IO>, Error>
where
    IO: AsRawFd + AsyncRead + AsyncWrite + Unpin,
{
    stream.get_mut().0.corked = true;
    let drained = drain(&mut stream).await.map_err(Error::DrainError)?;
    let (io, conn) = stream.into_inner();
    let io = io.io;

    setup_inner(io.as_raw_fd(), Connection::Client(conn))?;
    Ok(KtlsStream::new(io, drained))
}

/// Read all the bytes we can read without blocking. This is used to drained the
/// already-decrypted buffer from a tokio-rustls I/O type
async fn drain(stream: &mut (impl AsyncRead + Unpin)) -> std::io::Result<Option<Vec<u8>>> {
    tracing::trace!("Draining rustls stream");
    let mut drained = vec![0u8; 128 * 1024];
    let mut filled = 0;

    loop {
        tracing::trace!("stream.read called");
        let n = match stream.read(&mut drained[filled..]).await {
            Ok(n) => n,
            Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // actually this is expected for us!
                tracing::trace!("stream.read returned UnexpectedEof, that's expected for us");
                break;
            }
            Err(e) => {
                tracing::trace!("stream.read returned error: {e}");
                return Err(e);
            }
        };
        tracing::trace!("stream.read returned {n}");
        if n == 0 {
            // that's what CorkStream returns when it's at a message boundary
            break;
        }
        filled += n;
    }

    let maybe_drained = if filled == 0 {
        None
    } else {
        tracing::trace!("Draining rustls stream done: drained {filled} bytes");
        drained.resize(filled, 0);
        Some(drained)
    };
    Ok(maybe_drained)
}

fn setup_inner(fd: RawFd, conn: Connection) -> Result<(), Error> {
    let cipher_suite = match conn.negotiated_cipher_suite() {
        Some(cipher_suite) => cipher_suite,
        None => {
            return Err(Error::NoNegotiatedCipherSuite);
        }
    };

    let secrets = match conn.dangerous_extract_secrets() {
        Ok(secrets) => secrets,
        Err(err) => return Err(Error::ExportSecrets(err)),
    };

    ffi::setup_ulp(fd).map_err(Error::UlpError)?;

    let tx = CryptoInfo::from_rustls(cipher_suite, secrets.tx)?;
    setup_tls_info(fd, ffi::Direction::Tx, tx)?;

    let rx = CryptoInfo::from_rustls(cipher_suite, secrets.rx)?;
    setup_tls_info(fd, ffi::Direction::Rx, rx)?;

    Ok(())
}

/// TLS versions supported by this crate
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub enum KtlsVersion {
    TLS12,
    TLS13,
}

impl KtlsVersion {
    /// Converts into the equivalent rustls [SupportedProtocolVersion]
    pub fn as_supported_version(&self) -> &'static SupportedProtocolVersion {
        match self {
            KtlsVersion::TLS12 => &rustls::version::TLS12,
            KtlsVersion::TLS13 => &rustls::version::TLS13,
        }
    }
}

/// A TLS cipher suite. Used mostly internally.
#[derive(Clone, Copy)]
pub struct KtlsCipherSuite {
    /// The TLS version
    pub version: KtlsVersion,

    /// The cipher type
    pub typ: KtlsCipherType,
}

/// Cipher types supported by this crate
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub enum KtlsCipherType {
    AesGcm128,
    AesGcm256,
    Chacha20Poly1305,
}

#[derive(Debug, thiserror::Error)]
pub enum CipherSuiteError {
    #[error("TLS 1.2 support not built in")]
    Tls12NotBuiltIn,

    #[error("unsupported cipher suite")]
    UnsupportedCipherSuite(SupportedCipherSuite),
}

impl TryFrom<SupportedCipherSuite> for KtlsCipherSuite {
    type Error = CipherSuiteError;

    fn try_from(#[allow(unused)] suite: SupportedCipherSuite) -> Result<Self, Self::Error> {
        {
            let version = match suite {
                SupportedCipherSuite::Tls12(..) => {
                    if !cfg!(feature = "tls12") {
                        return Err(CipherSuiteError::Tls12NotBuiltIn);
                    }
                    KtlsVersion::TLS12
                }
                SupportedCipherSuite::Tls13(..) => KtlsVersion::TLS13,
            };

            let family = {
                if suite == cipher_suite::TLS13_AES_128_GCM_SHA256 {
                    KtlsCipherType::AesGcm128
                } else if suite == cipher_suite::TLS13_AES_256_GCM_SHA384 {
                    KtlsCipherType::AesGcm256
                } else if suite == cipher_suite::TLS13_CHACHA20_POLY1305_SHA256 {
                    KtlsCipherType::Chacha20Poly1305
                } else if suite == cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 {
                    KtlsCipherType::AesGcm128
                } else if suite == cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 {
                    KtlsCipherType::AesGcm256
                } else if suite == cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 {
                    KtlsCipherType::Chacha20Poly1305
                } else {
                    return Err(CipherSuiteError::UnsupportedCipherSuite(suite));
                }
            };

            Ok(Self {
                typ: family,
                version,
            })
        }
    }
}

impl KtlsCipherSuite {
    pub fn as_supported_cipher_suite(&self) -> SupportedCipherSuite {
        match self.version {
            KtlsVersion::TLS12 => match self.typ {
                KtlsCipherType::AesGcm128 => cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                KtlsCipherType::AesGcm256 => cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                KtlsCipherType::Chacha20Poly1305 => {
                    cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                }
            },
            KtlsVersion::TLS13 => match self.typ {
                KtlsCipherType::AesGcm128 => cipher_suite::TLS13_AES_128_GCM_SHA256,
                KtlsCipherType::AesGcm256 => cipher_suite::TLS13_AES_256_GCM_SHA384,
                KtlsCipherType::Chacha20Poly1305 => cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            },
        }
    }
}
