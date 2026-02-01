use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const UDP_BUF_SIZE: usize = 65535;
const CLEANUP_INTERVAL: Duration = Duration::from_secs(10);

struct ClientState {
    /// Ephemeral socket for communicating with the target on behalf of this client.
    socket: Arc<UdpSocket>,
    last_active: Instant,
    /// Cancel token for the return-path task.
    _cancel: CancellationToken,
}

/// Run a UDP port forwarder: listen on `listen_addr`, forward to `target`.
pub async fn run_udp_forwarder(
    listen_addr: SocketAddr,
    target: SocketAddr,
    cancel: CancellationToken,
) {
    let host_socket = match UdpSocket::bind(listen_addr).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("udp bind {listen_addr} failed: {e}");
            return;
        }
    };
    tracing::info!("udp forwarding {listen_addr} -> {target}");

    let host_socket = Arc::new(host_socket);
    let clients: Arc<Mutex<HashMap<SocketAddr, ClientState>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Periodic cleanup of idle client entries
    let cleanup_clients = clients.clone();
    let cleanup_cancel = cancel.child_token();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cleanup_cancel.cancelled() => break,
                _ = tokio::time::sleep(CLEANUP_INTERVAL) => {
                    let mut map = cleanup_clients.lock().await;
                    let now = Instant::now();
                    map.retain(|addr, entry| {
                        let alive = now.duration_since(entry.last_active) < UDP_IDLE_TIMEOUT;
                        if !alive {
                            tracing::debug!("udp client {addr} idle timeout");
                        }
                        alive
                        // Dropping ClientState cancels the return-path task via _cancel
                    });
                }
            }
        }
    });

    let mut buf = vec![0u8; UDP_BUF_SIZE];

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            result = host_socket.recv_from(&mut buf) => {
                let (n, client_addr) = match result {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!("udp recv on {listen_addr}: {e}");
                        continue;
                    }
                };

                let data = &buf[..n];
                let mut map = clients.lock().await;

                // Get or create per-client ephemeral socket
                if !map.contains_key(&client_addr) {
                    let std_sock = match std::net::UdpSocket::bind("0.0.0.0:0") {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::warn!("udp ephemeral bind for {client_addr}: {e}");
                            continue;
                        }
                    };
                    std_sock.set_nonblocking(true).unwrap();
                    let socket = Arc::new(UdpSocket::from_std(std_sock).unwrap());

                    let return_cancel = cancel.child_token();
                    // Spawn return-path task
                    tokio::spawn(udp_return_path(
                        host_socket.clone(),
                        socket.clone(),
                        client_addr,
                        return_cancel.child_token(),
                    ));

                    map.insert(client_addr, ClientState {
                        socket,
                        last_active: Instant::now(),
                        _cancel: return_cancel,
                    });
                }

                let entry = map.get_mut(&client_addr).unwrap();
                entry.last_active = Instant::now();

                // Forward client data to target
                if let Err(e) = entry.socket.send_to(data, target).await {
                    tracing::debug!("udp send to {target} for {client_addr}: {e}");
                }
            }
        }
    }
}

/// Return path: read from the per-client ephemeral socket, send back to the
/// original client via the host socket.
async fn udp_return_path(
    host_socket: Arc<UdpSocket>,
    client_socket: Arc<UdpSocket>,
    client_addr: SocketAddr,
    cancel: CancellationToken,
) {
    let mut buf = vec![0u8; UDP_BUF_SIZE];

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            result = client_socket.recv_from(&mut buf) => {
                let (n, _from) = match result {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::debug!("udp return recv for {client_addr}: {e}");
                        break;
                    }
                };
                if let Err(e) = host_socket.send_to(&buf[..n], client_addr).await {
                    tracing::debug!("udp return send to {client_addr}: {e}");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_udp_forward_roundtrip() {
        // UDP echo server
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; UDP_BUF_SIZE];
            loop {
                match echo.recv_from(&mut buf).await {
                    Ok((n, from)) => { let _ = echo.send_to(&buf[..n], from).await; }
                    Err(_) => break,
                }
            }
        });

        // Start forwarder
        let cancel = CancellationToken::new();
        // Bind to get a free port, then release and let forwarder bind
        let tmp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let fwd_addr = tmp.local_addr().unwrap();
        drop(tmp);

        let token = cancel.child_token();
        tokio::spawn(run_udp_forwarder(fwd_addr, echo_addr, token));
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Send through forwarder
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(b"hello udp", fwd_addr).await.unwrap();

        let mut buf = vec![0u8; 64];
        let (n, _) = tokio::time::timeout(
            Duration::from_secs(2),
            client.recv_from(&mut buf),
        ).await.unwrap().unwrap();
        assert_eq!(&buf[..n], b"hello udp");

        cancel.cancel();
    }
}
