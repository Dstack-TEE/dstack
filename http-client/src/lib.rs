// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::Request;
use hyper_util::client::legacy::Client;
use hyper_vsock::VsockClientExt;
use hyperlocal::{UnixClientExt, UnixConnector, Uri};
use log::debug;

mod hyper_vsock;

#[cfg(feature = "prpc")]
pub mod prpc;

fn mk_url(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('/');
    let path = path.trim_start_matches('/');
    format!("{base}/{path}")
}

/// Sends an HTTP request to the supervisor.
///
/// # Arguments
///
/// * `method` - The HTTP method to use.
/// * `uri` - The URI to send the request to. Supports Unix sockets: `unix:/path/to/socket` or HTTP: `http://host:port`.
/// * `body` - The body of the request.
pub async fn http_request(
    method: &str,
    base: &str,
    path: &str,
    body: &[u8],
) -> Result<(u16, Vec<u8>)> {
    debug!("Sending HTTP request to {base}, path={path}");
    let mut response = if let Some(uds) = base.strip_prefix("unix:") {
        let path = if path.starts_with("/") {
            path.to_string()
        } else {
            format!("/{path}")
        };
        let client: Client<UnixConnector, Full<Bytes>> = Client::unix();
        let unix_uri: hyper::Uri = Uri::new(uds, &path).into();
        let req = Request::builder()
            .method(method)
            .uri(unix_uri)
            .body(Full::new(Bytes::copy_from_slice(body)))?;
        client.request(req).await?
    } else if base.starts_with("vsock:") {
        let client = Client::vsock();
        let uri = mk_url(base, path).parse::<hyper::Uri>()?;
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .body(Full::new(Bytes::copy_from_slice(body)))?;
        client.request(req).await?
    } else {
        let uri = mk_url(base, path);
        let client = reqwest::Client::builder().build()?;
        let response = client.post(uri).body(body.to_vec()).send().await?;
        return Ok((
            response.status().as_u16(),
            response.text().await?.into_bytes(),
        ));
    };
    debug!("Response: {:?}", response);
    let mut body = Vec::new();
    while let Some(frame_result) = response.frame().await {
        let frame = frame_result?;
        if let Some(segment) = frame.data_ref() {
            body.extend_from_slice(segment.iter().as_slice());
        }
    }
    Ok((response.status().as_u16(), body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_vsock_uri_parsing() -> Result<(), Box<dyn Error>> {
        let uri = "vsock://2:1234/path".parse::<hyper::Uri>()?;
        assert_eq!(uri.scheme_str(), Some("vsock"));
        assert_eq!(uri.host(), Some("2"));
        assert_eq!(uri.port_u16(), Some(1234));
        assert_eq!(uri.path(), "/path");
        Ok(())
    }
}
