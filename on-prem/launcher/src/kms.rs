use anyhow::{Context, Result};
use dstack_kms_rpc::GetMetaResponse;
use prost::Message;

async fn prpc_post_raw<Resp>(
    client: &reqwest::Client,
    kms_url: &str,
    service_method: &str,
    body: Vec<u8>,
) -> Result<Resp>
where
    Resp: Message + Default,
{
    let url = format!("{}/prpc/{}", kms_url.trim_end_matches('/'), service_method);
    let response = client
        .post(&url)
        .header("content-type", "application/protobuf")
        .body(body)
        .send()
        .await
        .with_context(|| format!("failed to send request to {url}"))?;

    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .context("failed to read response body")?;

    if !status.is_success() {
        anyhow::bail!(
            "kms request to {url} failed with status {status}: {}",
            String::from_utf8_lossy(&bytes)
        );
    }

    Resp::decode(bytes.as_ref()).context("failed to decode protobuf response")
}

/// Fetch KMS metadata, notably the root CA cert used as the trust anchor for the
/// key-broker mTLS server cert. GetMeta is unauthenticated (public CA only).
pub async fn get_meta(kms_url: &str) -> Result<GetMetaResponse> {
    // GetMeta returns only the public CA; the connection's server cert isn't yet
    // trusted here, so accept it for this one metadata fetch.
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .context("failed to build http client")?;

    prpc_post_raw::<GetMetaResponse>(&client, kms_url, "KMS.GetMeta", Vec::new())
        .await
        .context("failed to call GetMeta")
}
