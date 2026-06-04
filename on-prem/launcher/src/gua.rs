// Guest-agent client over the local dstack.sock (prpc = protobuf over HTTP/1.1
// on a Unix socket). The workload CVM runs key_provider=kms, so the guest agent
// has already done RA-TLS GetAppKey against our KMS at boot; here we ask it for
// an RA-TLS *client* cert (KMS-CA-signed, with the app_info extension) to use as
// the launcher's identity to the key-broker mTLS — no self-signed fallback.
use anyhow::{bail, Context, Result};
use bytes::Bytes;
use dstack_guest_agent_rpc::{GetTlsKeyArgs, GetTlsKeyResponse};
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
use prost::Message;
use tokio::net::UnixStream;

/// Ask the guest agent for an RA-TLS client cert + key (KMS-signed chain).
/// Returns (private_key_pem, certificate_chain_pem).
pub async fn get_tls_key(sock_path: &str) -> Result<(String, Vec<String>)> {
    let args = GetTlsKeyArgs {
        subject: "dstack-launcher".to_string(),
        alt_names: vec![],
        usage_ra_tls: true,        // embed the TDX+vTPM quote (RA-TLS)
        usage_server_auth: false,
        usage_client_auth: true,   // this cert authenticates us to the key-broker
        not_before: None,
        not_after: None,
        with_app_info: true,       // embed app_id/compose_hash/os_image for the broker
    };
    let body = Bytes::from(args.encode_to_vec());

    let stream = UnixStream::connect(sock_path)
        .await
        .with_context(|| format!("failed to connect guest-agent socket {sock_path}"))?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .context("guest-agent http1 handshake failed")?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    // The guest agent mounts the DstackGuest prpc service at "/" on dstack.sock
    // with no trim prefix, so the route is the bare method name "/GetTlsKey"
    // (unlike the KMS, mounted at "/prpc" with trim "KMS." → "/prpc/KMS.GetMeta").
    let req = Request::builder()
        .method("POST")
        .uri("/GetTlsKey")
        .header("host", "localhost")
        .header("content-type", "application/protobuf")
        .body(Full::new(body))
        .context("failed to build guest-agent request")?;

    let resp = sender
        .send_request(req)
        .await
        .context("guest-agent GetTlsKey request failed")?;
    let status = resp.status();
    let buf = resp
        .into_body()
        .collect()
        .await
        .context("failed to read guest-agent response")?
        .to_bytes();
    if !status.is_success() {
        bail!(
            "guest-agent GetTlsKey returned {status}: {}",
            String::from_utf8_lossy(&buf)
        );
    }
    let r = GetTlsKeyResponse::decode(buf.as_ref()).context("failed to decode GetTlsKeyResponse")?;
    if r.key.is_empty() || r.certificate_chain.is_empty() {
        bail!("guest-agent returned an empty TLS key/chain");
    }
    Ok((r.key, r.certificate_chain))
}
