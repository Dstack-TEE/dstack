// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    task::Poll,
};

use anyhow::{bail, Context, Result};
use http_client::ConnectionReuse;
use or_panic::ResultOrPanic;
use sni::extract_sni;
pub(crate) use tls_passthough::AppAddressResolver;
pub(crate) use tls_terminate::create_acceptor_with_cert_resolver;
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    runtime::Runtime,
    time::timeout,
};
use tracing::{debug, debug_span, error, info, warn, Instrument};

use crate::{
    config::ProxyConfig,
    main_service::Proxy,
    models::EnteredCounter,
    pp::{get_inbound_pp_header, DisplayAddr},
};

#[derive(Debug, Clone)]
pub(crate) struct AddressInfo {
    pub ip: Ipv4Addr,
    pub counter: Arc<AtomicU64>,
    /// Instance id this address belongs to. Used to look up per-instance state
    /// (e.g. port_policy) after the racing connect picks a winner.
    pub instance_id: String,
}

pub(crate) type AddressGroup = smallvec::SmallVec<[AddressInfo; 4]>;

mod adaptive_ktls;
mod balance;
/// Largest response the gateway will read from a guest agent.
///
/// `Worker.Health` returns a bool and a short list, so this is generous for the
/// poller. It is sized for the other guest-facing call: `DstackGuest.Info`
/// carries `tcb_info`, which embeds the app's entire `app_compose` -- including
/// `docker_compose_file` verbatim. Nothing caps how large an app-compose may
/// be, and a legacy CVM whose `Info` exceeds this never gets a port policy and
/// is denied permanently, so the bound has to sit well above any plausible
/// compose file rather than merely above a health response.
const MAX_GUEST_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// A prpc client for a CVM's guest agent.
///
/// The one place that decides how the gateway talks to a guest agent, because
/// that peer is the one dstack's threat model does not trust -- the reason
/// health is polled rather than pushed. Bounding the response is a per-caller
/// opt-in in `http-client` (a transport-wide cap would break `dstack vmm
/// logs`), so it has to be applied somewhere; applying it here means a new
/// guest-facing client cannot forget.
///
/// `reuse` is an argument rather than a default for the opposite reason: the
/// two guest-facing callers want different answers and neither is obviously
/// right, so the compiler asks. See [`ConnectionReuse`].
pub(crate) fn guest_agent_client(
    url: String,
    reuse: ConnectionReuse,
) -> http_client::prpc::PrpcClient {
    http_client::prpc::PrpcClient::new(url)
        .with_max_response_bytes(MAX_GUEST_RESPONSE_BYTES)
        .with_connection_reuse(reuse)
}

pub(crate) mod health_check;
mod idle;
mod io_bridge;
pub(crate) mod port_policy;
mod reuseport;
mod sni;
mod splice;
pub(crate) mod stats;
mod tls_passthough;
mod tls_terminate;

async fn take_sni(stream: &mut TcpStream) -> Result<(Option<String>, Vec<u8>)> {
    let mut buffer = vec![0u8; 4096];
    let mut data_len = 0;
    loop {
        // read data from stream
        let n = stream
            .read(&mut buffer[data_len..])
            .await
            .context("failed to read from incoming tcp stream")?;
        if n == 0 {
            break;
        }
        data_len += n;

        if let Some(sni) = extract_sni(&buffer[..data_len]) {
            let sni = String::from_utf8(sni.to_vec()).context("sni: invalid utf-8")?;
            debug!("got sni: {sni}");
            buffer.truncate(data_len);
            return Ok((Some(sni), buffer));
        }
    }
    buffer.truncate(data_len);
    Ok((None, buffer))
}

#[derive(Debug)]
struct DstInfo {
    app_id: String,
    port: u16,
    is_tls: bool,
    is_h2: bool,
}

fn parse_dst_info(subdomain: &str) -> Result<DstInfo> {
    let mut parts = subdomain.split('-');
    let app_id = parts.next().context("no app id found")?.to_owned();
    if app_id.is_empty() {
        bail!("app id is empty");
    }
    let last_part = parts.next();
    let is_tls;
    let port;
    let is_h2;
    match last_part {
        None => {
            is_tls = false;
            is_h2 = false;
            port = None;
        }
        Some(last_part) => {
            let (port_str, has_g) = match last_part.strip_suffix('g') {
                Some(without_g) => (without_g, true),
                None => (last_part, false),
            };

            let (port_str, has_s) = match port_str.strip_suffix('s') {
                Some(without_s) => (without_s, true),
                None => (port_str, false),
            };
            if has_g && has_s {
                bail!("invalid sni format: `gs` is not allowed");
            }
            is_h2 = has_g;
            is_tls = has_s;
            port = if port_str.is_empty() {
                None
            } else {
                Some(port_str.parse::<u16>().context("invalid port")?)
            };
        }
    };
    let port = port.unwrap_or(if is_tls { 443 } else { 80 });
    if parts.next().is_some() {
        bail!("invalid sni format");
    }
    Ok(DstInfo {
        app_id,
        port,
        is_tls,
        is_h2,
    })
}

pub static NUM_CONNECTIONS: AtomicU64 = AtomicU64::new(0);

async fn handle_connection(inbound: TcpStream, state: Proxy) -> Result<()> {
    let timeouts = &state.config.proxy.timeouts;

    let pp_fut = get_inbound_pp_header(inbound, &state.config.proxy);
    let (mut inbound, pp_header) = timeout(timeouts.pp_header, pp_fut)
        .await
        .context("proxy protocol header timeout")?
        .context("failed to read proxy protocol header")?;
    debug!("client address: {}", DisplayAddr(&pp_header));

    let (sni, buffer) = timeout(timeouts.handshake, take_sni(&mut inbound))
        .await
        .context("take sni timeout")?
        .context("failed to take sni")?;
    let Some(sni) = sni else {
        bail!("no sni found");
    };

    let (subdomain, base_domain) = sni.split_once('.').context("invalid sni")?;
    if state.cert_resolver.get().contains_wildcard(base_domain) {
        let dst = parse_dst_info(subdomain)?;
        debug!("dst: {dst:?}");
        if dst.is_tls {
            tls_passthough::proxy_to_app(state, inbound, pp_header, buffer, &dst.app_id, dst.port)
                .await
        } else {
            state
                .proxy(inbound, pp_header, buffer, &dst.app_id, dst.port, dst.is_h2)
                .await
        }
    } else {
        tls_passthough::proxy_with_sni(state, inbound, pp_header, buffer, &sni).await
    }
}

/// Bind one listener per configured port.
///
/// With `reuse_port` every worker binds its own listener on the same port and
/// the kernel spreads incoming connections across them, so each worker can
/// accept and serve its connections without any cross-thread handoff.
/// Accept queue depth. tokio's default is 1024, which is where SYN drops start
/// under connection bursts; both listen paths use this so they behave alike.
const LISTEN_BACKLOG: i32 = 4096;

async fn bind_listeners(config: &ProxyConfig, reuse_port: bool) -> Result<Vec<TcpListener>> {
    let mut tcp_listeners = Vec::new();
    for &port in &config.listen_port {
        let listener = {
            let addr = std::net::SocketAddr::from((config.listen_addr, port));
            let socket = socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )
            .context("failed to create listening socket")?;
            if reuse_port {
                socket
                    .set_reuse_port(true)
                    .context("failed to set SO_REUSEPORT")?;
            }
            socket.set_reuse_address(true).ok();
            socket.set_nonblocking(true).ok();
            socket
                .bind(&addr.into())
                .with_context(|| format!("failed to bind {addr}"))?;
            socket.listen(LISTEN_BACKLOG).context("failed to listen")?;
            TcpListener::from_std(std::net::TcpListener::from(socket))
                .context("failed to register listener with tokio")?
        };
        info!("tcp bridge listening on {}:{}", config.listen_addr, port);
        tcp_listeners.push(listener);
    }
    Ok(tcp_listeners)
}

#[inline(never)]
pub async fn proxy_main(rt: &Runtime, config: &ProxyConfig, proxy: Proxy) -> Result<()> {
    let tcp_listeners = bind_listeners(config, false).await?;
    accept_loop(tcp_listeners, proxy, Some(rt), None).await
}

/// The per-connection task: everything a single proxied connection does.
/// Was this failure just the peer hanging up?
///
/// Clients disconnecting mid-connection is routine -- a browser navigating away,
/// a mobile network dropping, a load generator ending its run. Logging those at
/// error level buries the failures that are actually the gateway's fault: a 40
/// minute soak produced 379 such lines and no real errors.
fn is_peer_disconnect(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause.downcast_ref::<std::io::Error>().is_some_and(|io| {
            matches!(
                io.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionAborted
            )
        })
    })
}

fn conn_task(
    inbound: TcpStream,
    from: std::net::SocketAddr,
    proxy: Proxy,
    slot: Option<balance::CoreSlot>,
) -> impl std::future::Future<Output = ()> + Send + 'static {
    let span = debug_span!("conn", id = next_connection_id());
    let conn_entered = EnteredCounter::new(&NUM_CONNECTIONS);
    async move {
        let _conn_entered = conn_entered;
        let _slot = slot;
        debug!(%from, "new connection");
        let timeouts = &proxy.config.proxy.timeouts;
        match timeout(timeouts.total, handle_connection(inbound, proxy)).await {
            Ok(Ok(_)) => debug!("connection closed"),
            Ok(Err(e)) if is_peer_disconnect(&e) => debug!("peer disconnected: {e:#}"),
            Ok(Err(e)) => error!("connection error: {e:#}"),
            Err(_) => error!("connection kept too long, force closing"),
        }
    }
    .instrument(span)
}

/// Accept connections forever.
///
/// `rt` selects where connections run: `Some(worker_rt)` hands them to a shared
/// multi-threaded runtime, `None` keeps them on the calling thread's own
/// runtime (thread-per-core), which avoids the cross-thread handoff and the
/// work-stealing migrations that come with it.
async fn accept_loop(
    tcp_listeners: Vec<TcpListener>,
    proxy: Proxy,
    rt: Option<&Runtime>,
    mut balance: Option<(
        balance::Balancer,
        tokio::sync::mpsc::Receiver<balance::Handoff>,
    )>,
) -> Result<()> {
    if tcp_listeners.is_empty() {
        bail!("no tcp listen ports configured");
    }
    let poll_counter = AtomicUsize::new(0);
    loop {
        // Accept from any TCP listener via round-robin poll.
        let poll_start = poll_counter.fetch_add(1, Ordering::Relaxed);
        let n = tcp_listeners.len();
        let accept_next = std::future::poll_fn(|cx| {
            for j in 0..n {
                let i = (poll_start + j) % n;
                if let Poll::Ready(result) = tcp_listeners[i].poll_accept(cx) {
                    return Poll::Ready(result);
                }
            }
            Poll::Pending
        });
        // Also take connections other cores decided to give us.
        let accepted: std::io::Result<(TcpStream, std::net::SocketAddr)> = match balance.as_mut() {
            Some((_, rx)) => {
                tokio::select! {
                    r = accept_next => r,
                    Some((raw, from, slot)) = rx.recv() => {
                        // Register the handed-over socket with *this* core's reactor.
                        match TcpStream::from_std(raw) {
                            Ok(stream) => {
                                let task = conn_task(stream, from, proxy.clone(), Some(slot));
                                tokio::spawn(task);
                            }
                            Err(e) => error!("failed to adopt handed-over connection: {e}"),
                        }
                        continue;
                    }
                }
            }
            None => accept_next.await,
        };
        match accepted {
            Ok((inbound, from)) => {
                // Disable Nagle: this is a latency-sensitive proxy and small
                // request/response traffic otherwise stalls on delayed ACKs.
                let _ = inbound.set_nodelay(true);
                // In thread-per-core mode, hand the connection to a less loaded
                // core when this one is running ahead; SO_REUSEPORT's hash can
                // leave a core starved and it cannot be fixed later.
                let placed: Option<(TcpStream, Option<balance::CoreSlot>)> = match balance.as_ref()
                {
                    Some((b, _)) => b.place(inbound, from).map(|(s, slot)| (s, Some(slot))),
                    None => Some((inbound, None)),
                };
                if let Some((inbound, slot)) = placed {
                    let task = conn_task(inbound, from, proxy.clone(), slot);
                    match rt {
                        Some(rt) => {
                            rt.spawn(task);
                        }
                        None => {
                            tokio::spawn(task);
                        }
                    }
                }
            }
            Err(e) => {
                error!("failed to accept connection: {e:?}");
            }
        }
    }
}

fn next_connection_id() -> usize {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

pub fn start(config: ProxyConfig, app_state: Proxy) -> Result<()> {
    if config.thread_per_core {
        // Probe SO_REUSEPORT before committing: it is the one prerequisite the
        // thread-per-core model cannot work without, and failing to serve at all
        // is far worse than losing the optimisation.
        match probe_reuse_port(&config) {
            Ok(()) => return start_thread_per_core(config, app_state),
            Err(err) => warn!(
                "thread_per_core requested but SO_REUSEPORT is unavailable ({err:#}); \
                 falling back to the shared-runtime proxy"
            ),
        }
    }
    if config.connection_rebalance {
        // It is only wired up by the thread-per-core path: there is nothing to
        // rebalance between when every connection lands on a shared runtime.
        warn!(
            "connection_rebalance is set but has no effect without thread_per_core; \
             the shared-runtime proxy balances connections through its scheduler"
        );
    }
    std::thread::Builder::new()
        .name("proxy-main".to_string())
        .spawn(move || {
            // Create a new single-threaded runtime
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .or_panic("Failed to build Tokio runtime");

            let worker_rt = tokio::runtime::Builder::new_multi_thread()
                .thread_name("proxy-worker")
                .enable_all()
                .worker_threads(config.workers)
                .build()
                .or_panic("Failed to build Tokio runtime");

            // Run the proxy_main function in this runtime
            if let Err(err) = rt.block_on(proxy_main(&worker_rt, &config, app_state)) {
                error!(
                    "error on {}:{:?}: {err:?}",
                    config.listen_addr, config.listen_port
                );
            }
        })
        .context("Failed to spawn proxy-main thread")?;
    Ok(())
}

/// Check that a `SO_REUSEPORT` listener can actually be created and bound.
fn probe_reuse_port(config: &ProxyConfig) -> Result<()> {
    let port = *config
        .listen_port
        .first()
        .context("no tcp listen ports configured")?;
    let addr = std::net::SocketAddr::from((config.listen_addr, port));
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )
    .context("failed to create probe socket")?;
    socket
        .set_reuse_port(true)
        .context("SO_REUSEPORT not supported")?;
    socket.set_reuse_address(true).ok();
    socket
        .bind(&addr.into())
        .with_context(|| format!("failed to bind {addr} with SO_REUSEPORT"))?;
    Ok(())
}

/// Turn kTLS off when the kernel cannot provide it.
///
/// Without the TLS ULP an immediate offload fails every handshake, which is at
/// least loud. A gated offload is worse: the connection is served from
/// userspace up to the threshold and only then fails, so the client gets a
/// successful response truncated at exactly the gate. Both are worse than never
/// offloading, and whether the ULP is there is not something the config can
/// know -- so ask the kernel once, at startup, before the acceptor is built
/// (that is also what decides whether rustls extracts session secrets at all).
///
/// This only establishes that the ULP exists. A cipher suite the kernel does
/// not implement still fails per connection, at offload time.
pub fn disable_ktls_if_unsupported(config: &mut ProxyConfig) {
    if config.ktls.is_none() {
        return;
    }
    if let Err(err) = probe_ktls() {
        warn!(
            "kTLS is configured but unavailable ({err:#}); \
             falling back to userspace TLS record encryption"
        );
        config.ktls = None;
        stats::mark_ktls_unsupported();
    }
}

/// Check that the kernel exposes the TLS upper-layer protocol.
///
/// `TCP_ULP` is only accepted on an established socket, so this sets up a
/// throwaway loopback connection instead of probing a fresh one, which would
/// fail with `ENOTCONN` whether or not the ULP exists.
#[cfg(target_os = "linux")]
fn probe_ktls() -> Result<()> {
    use std::net::{Ipv4Addr, TcpListener, TcpStream};
    use std::os::fd::AsRawFd;

    /// `include/uapi/linux/tcp.h`; not exposed by the `libc` crate.
    const TCP_ULP: libc::c_int = 31;

    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).context("failed to bind the probe listener")?;
    let addr = listener
        .local_addr()
        .context("failed to read the probe listener address")?;
    let client = TcpStream::connect(addr).context("failed to connect the probe socket")?;
    let _server = listener
        .accept()
        .context("failed to accept the probe socket")?;

    let name = c"tls";
    // SAFETY: `name` outlives the call and `len` matches it, NUL included.
    let rc = unsafe {
        libc::setsockopt(
            client.as_raw_fd(),
            libc::IPPROTO_TCP,
            TCP_ULP,
            name.as_ptr().cast(),
            name.to_bytes_with_nul().len() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .context("kernel rejected the TLS ULP (is CONFIG_TLS enabled?)");
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn probe_ktls() -> Result<()> {
    bail!("kernel TLS is only available on Linux")
}

/// Thread-per-core proxy: `workers` threads, each with its own single-threaded
/// runtime and its own `SO_REUSEPORT` listener.
///
/// The kernel load-balances new connections across the listeners, and a
/// connection is accepted and served entirely on one thread. That removes the
/// accept-thread -> worker handoff and the work-stealing scheduler's task
/// migrations, which together accounted for ~0.6 context switches per request
/// in the default model.
fn start_thread_per_core(config: ProxyConfig, app_state: Proxy) -> Result<()> {
    let workers = config.workers.max(1);
    // Bind every listener here, in order, rather than letting each thread bind
    // its own. The CBPF steering program that originally needed a known group
    // order is gone (see `super::reuseport`), but binding in one place is kept:
    // it keeps listener-to-core assignment deterministic across restarts, and it
    // fails startup as a whole if any bind fails, instead of leaving some cores
    // serving and others dead.
    let mut per_worker: Vec<Vec<std::net::TcpListener>> =
        (0..workers).map(|_| Vec::new()).collect();
    for &port in &config.listen_port {
        let addr = std::net::SocketAddr::from((config.listen_addr, port));
        let group = reuseport::bind_group(addr, workers, LISTEN_BACKLOG)
            .with_context(|| format!("failed to bind reuseport group on {addr}"))?;
        info!(
            "tcp bridge listening on {}:{} across {} listeners",
            config.listen_addr, port, workers
        );
        for (i, l) in group.into_iter().enumerate() {
            per_worker[i].push(l);
        }
    }

    // Per-core balancers share the connection counts; each core also gets the
    // receiving end of its handoff channel.
    let (balancers, receivers) = if config.connection_rebalance {
        let (b, r) = balance::Balancer::build(workers);
        (
            b.into_iter().map(Some).collect(),
            r.into_iter().map(Some).collect(),
        )
    } else {
        (
            (0..workers).map(|_| None).collect::<Vec<_>>(),
            (0..workers).map(|_| None).collect::<Vec<_>>(),
        )
    };

    let config = Arc::new(config);
    for (i, ((std_listeners, balancer), receiver)) in per_worker
        .into_iter()
        .zip(balancers)
        .zip(receivers)
        .enumerate()
    {
        let config = config.clone();
        let app_state = app_state.clone();
        std::thread::Builder::new()
            .name(format!("proxy-core-{i}"))
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .or_panic("Failed to build Tokio runtime");
                let result = rt.block_on(async {
                    let mut listeners = Vec::with_capacity(std_listeners.len());
                    for l in std_listeners {
                        listeners.push(
                            TcpListener::from_std(l)
                                .context("failed to register listener with tokio")?,
                        );
                    }
                    let bal = balancer.zip(receiver);
                    accept_loop(listeners, app_state, None, bal).await
                });
                if let Err(err) = result {
                    error!(
                        "proxy core {i} error on {}:{:?}: {err:?}",
                        config.listen_addr, config.listen_port
                    );
                }
            })
            .with_context(|| format!("Failed to spawn proxy-core-{i} thread"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_proxy_config() -> ProxyConfig {
        crate::config::load_config_figment(None)
            .focus("core.proxy")
            .extract()
            .expect("the shipped default config should parse")
    }

    #[test]
    fn ktls_probe_leaves_an_unconfigured_gateway_alone() {
        let mut config = default_proxy_config();
        config.ktls = None;
        disable_ktls_if_unsupported(&mut config);
        assert!(config.ktls.is_none());
    }

    #[test]
    fn ktls_survives_the_probe_only_when_the_kernel_supports_it() {
        let mut config = default_proxy_config();
        config.ktls = Some(crate::config::EngageAfter::default());
        disable_ktls_if_unsupported(&mut config);
        // Whichever way this kernel answers, the config must agree with it:
        // keeping kTLS on a kernel without the ULP is what truncates responses
        // at the gate.
        assert_eq!(config.ktls.is_some(), probe_ktls().is_ok());
    }

    #[test]
    fn test_parse_destination() {
        // Test basic app_id only
        let result = parse_dst_info("myapp").unwrap();
        assert_eq!(result.app_id, "myapp");
        assert_eq!(result.port, 80);
        assert!(!result.is_tls);

        // Test app_id with custom port
        let result = parse_dst_info("myapp-8080").unwrap();
        assert_eq!(result.app_id, "myapp");
        assert_eq!(result.port, 8080);
        assert!(!result.is_tls);

        // Test app_id with TLS
        let result = parse_dst_info("myapp-443s").unwrap();
        assert_eq!(result.app_id, "myapp");
        assert_eq!(result.port, 443);
        assert!(result.is_tls);

        // Test app_id with custom port and TLS
        let result = parse_dst_info("myapp-8443s").unwrap();
        assert_eq!(result.app_id, "myapp");
        assert_eq!(result.port, 8443);
        assert!(result.is_tls);

        // Test default port but ends with s
        let result = parse_dst_info("myapps").unwrap();
        assert_eq!(result.app_id, "myapps");
        assert_eq!(result.port, 80);
        assert!(!result.is_tls);

        // Test default port but ends with s in port part
        let result = parse_dst_info("myapp-s").unwrap();
        assert_eq!(result.app_id, "myapp");
        assert_eq!(result.port, 443);
        assert!(result.is_tls);
    }
}
