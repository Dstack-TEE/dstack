// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Which VMMs to watch: a config file, `--node` flags, and, when neither
//! names any, the VMMs running on this host.
//!
//! ```toml
//! # ~/.config/dstack/vmm-top.toml
//! interval = "2s"
//!
//! [[node]]
//! name = "tdx-01"
//! url = "http://10.0.0.11:9080"
//! token_env = "TDX01_VMM_TOKEN"
//!
//! ```

use crate::source::SourceSpec;
use anyhow::{bail, Context, Result};
use fs_err as fs;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Token used for any VMM that names none, as with `dstack` and `vmm-cli.py`.
pub const VMM_TOKEN_ENV: &str = "DSTACK_VMM_TOKEN";
/// The control socket `dstackup install` creates.
pub const DEFAULT_SOCKET: &str = "/var/run/dstack/vmm.sock";

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    #[serde(default)]
    pub interval: Option<String>,
    /// Also watch the VMMs registered on this host. Defaults to on only when
    /// nothing else is configured.
    #[serde(default)]
    pub discover: Option<bool>,
    #[serde(default, rename = "node")]
    pub nodes: Vec<Entry>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    #[serde(default)]
    pub name: Option<String>,
    pub url: String,
    #[serde(default)]
    pub token: Option<String>,
    /// Name of an environment variable holding the token; keeps it out of
    /// the file.
    #[serde(default)]
    pub token_env: Option<String>,
}

pub fn default_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("dstack").join("vmm-top.toml"))
}

/// Read `path`, or the default file when `path` is `None`. A missing default
/// file is an empty config; a missing named one is an error.
pub fn load(path: Option<&Path>) -> Result<FileConfig> {
    let (path, required) = match path {
        Some(p) => (p.to_path_buf(), true),
        None => match default_path() {
            Some(p) => (p, false),
            None => return Ok(FileConfig::default()),
        },
    };
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) if !required && err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(FileConfig::default())
        }
        Err(err) => return Err(err.into()),
    };
    toml::from_str(&text).with_context(|| format!("failed to parse {}", path.display()))
}

pub fn resolve_token(token: Option<&str>, token_env: Option<&str>) -> Result<Option<String>> {
    if let Some(var) = token_env {
        return match std::env::var(var) {
            Ok(v) if !v.trim().is_empty() => Ok(Some(v.trim().to_string())),
            _ => bail!("environment variable {var} is not set"),
        };
    }
    Ok(token
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_string))
}

fn env_token() -> Option<String> {
    std::env::var(VMM_TOKEN_ENV)
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
}

/// `NAME=URL` or a bare `URL`.
pub fn parse_flag(flag: &str) -> (Option<String>, String) {
    if let Some((name, url)) = flag.split_once('=') {
        if !name.is_empty() && !name.contains(['/', ':']) {
            return (Some(name.to_string()), url.to_string());
        }
    }
    (None, flag.to_string())
}

/// A name for a source given only its address: the host of a URL, `local`
/// for a socket.
pub fn name_from_url(url: &str) -> String {
    if url.starts_with("unix:") {
        return "local".into();
    }
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split('/').next().unwrap_or(rest);
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if host.starts_with('[') {
        host.split_once(']')
            .map_or(host, |(h, _)| h.trim_start_matches('['))
    } else {
        host.split(':').next().unwrap_or(host)
    };
    if host.is_empty() {
        url.to_string()
    } else {
        host.to_string()
    }
}

pub struct Flags<'a> {
    pub nodes: &'a [String],
    /// For VMMs that name no token of their own.
    pub token: Option<&'a str>,
}

/// Every source to watch, with unique names.
pub fn sources(file: &FileConfig, flags: Flags) -> Result<Vec<SourceSpec>> {
    let fallback = flags.token.map(str::to_string).or_else(env_token);
    let mut out = Vec::new();
    for e in &file.nodes {
        out.push(entry_spec(e, fallback.clone())?);
    }
    for flag in flags.nodes {
        let (name, url) = parse_flag(flag);
        out.push(SourceSpec {
            name: name.unwrap_or_else(|| name_from_url(&url)),
            url,
            token: fallback.clone(),
        });
    }
    if file.discover.unwrap_or(out.is_empty()) {
        out.extend(discover(fallback.as_deref()));
    }
    if out.is_empty() && Path::new(DEFAULT_SOCKET).exists() {
        out.push(SourceSpec {
            name: "local".into(),
            url: format!("unix:{DEFAULT_SOCKET}"),
            token: fallback,
        });
    }
    dedupe_names(&mut out);
    Ok(out)
}

fn entry_spec(e: &Entry, fallback: Option<String>) -> Result<SourceSpec> {
    let token = resolve_token(e.token.as_deref(), e.token_env.as_deref())
        .with_context(|| format!("token for {}", e.url))?
        .or(fallback);
    Ok(SourceSpec {
        name: e.name.clone().unwrap_or_else(|| name_from_url(&e.url)),
        url: e.url.clone(),
        token,
    })
}

/// `name`, `name-2`, `name-3`, … so every node key is distinct.
pub fn dedupe_names(specs: &mut [SourceSpec]) {
    let mut seen: HashMap<String, usize> = HashMap::new();
    for s in specs.iter_mut() {
        let n = seen.entry(s.name.clone()).or_insert(0);
        *n += 1;
        if *n > 1 {
            s.name = format!("{}-{n}", s.name);
        }
    }
}

#[derive(Debug, Deserialize)]
struct Registration {
    pid: u32,
    address: String,
    #[serde(default)]
    working_dir: String,
    #[serde(default)]
    node_name: String,
    #[serde(default)]
    started_at: u64,
}

/// The VMMs this user runs on this host, from the registration files each
/// `dstack-vmm` writes at startup (see `vmm/src/discovery.rs`).
pub fn discover(token: Option<&str>) -> Vec<SourceSpec> {
    let dir = match std::env::var("XDG_RUNTIME_DIR") {
        Ok(x) if !x.is_empty() => PathBuf::from(x).join("dstack-vmm"),
        // SAFETY: getuid has no preconditions and cannot fail.
        _ => PathBuf::from(format!("/run/user/{}/dstack-vmm", unsafe {
            libc::getuid()
        })),
    };
    let Ok(entries) = fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut regs: Vec<Registration> = entries
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .filter_map(|e| fs::read(e.path()).ok())
        .filter_map(|b| serde_json::from_slice::<Registration>(&b).ok())
        .filter(|r| Path::new(&format!("/proc/{}", r.pid)).exists())
        .collect();
    regs.sort_by_key(|r| r.started_at);
    regs.into_iter()
        .filter_map(|r| {
            let url = registration_url(&r.address, &r.working_dir)?;
            Some(SourceSpec {
                name: if r.node_name.is_empty() {
                    "local".into()
                } else {
                    r.node_name
                },
                url,
                token: token.map(str::to_string),
            })
        })
        .collect()
}

/// The address a VMM registered, as something to connect to.
pub fn registration_url(address: &str, working_dir: &str) -> Option<String> {
    if let Some(sock) = address.strip_prefix("unix:") {
        let path = Path::new(sock);
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            Path::new(working_dir).join(path)
        };
        return Some(format!("unix:{}", path.display()));
    }
    if address.starts_with("http://") || address.starts_with("https://") {
        return Some(address.to_string());
    }
    let (host, port) = address.rsplit_once(':')?;
    let host = match host {
        "0.0.0.0" | "" => "127.0.0.1",
        "[::]" | "::" => "[::1]",
        h => h,
    };
    Some(format!("http://{host}:{port}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_take_optional_name() {
        assert_eq!(
            parse_flag("tdx=http://h:1"),
            (Some("tdx".into()), "http://h:1".into())
        );
        assert_eq!(
            parse_flag("http://h:1/?a=b"),
            (None, "http://h:1/?a=b".into())
        );
        assert_eq!(parse_flag("unix:/x=y"), (None, "unix:/x=y".into()));
    }

    #[test]
    fn names_come_from_hosts() {
        assert_eq!(name_from_url("http://10.0.0.1:9080"), "10.0.0.1");
        assert_eq!(name_from_url("https://u:p@vmm.example/x"), "vmm.example");
        assert_eq!(name_from_url("http://[fe80::1]:80"), "fe80::1");
        assert_eq!(name_from_url("unix:/run/vmm.sock"), "local");
    }

    #[test]
    fn registration_addresses() {
        assert_eq!(
            registration_url("unix:./vmm.sock", "/srv/vmm").as_deref(),
            Some("unix:/srv/vmm/./vmm.sock")
        );
        assert_eq!(
            registration_url("0.0.0.0:9080", "/").as_deref(),
            Some("http://127.0.0.1:9080")
        );
        assert_eq!(
            registration_url("http://h:1", "/").as_deref(),
            Some("http://h:1")
        );
    }

    #[test]
    fn duplicate_names_get_suffixes() {
        let spec = |n: &str| SourceSpec {
            name: n.into(),
            url: "unix:/x".into(),
            token: None,
        };
        let mut v = vec![spec("a"), spec("a"), spec("b"), spec("a")];
        dedupe_names(&mut v);
        let names: Vec<_> = v.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["a", "a-2", "b", "a-3"]);
    }

    #[test]
    fn config_file_parses() {
        let cfg: FileConfig = toml::from_str(
            r#"
            interval = "5s"
            [[node]]
            name = "a"
            url = "http://a:1"
            token = "t"
            [[node]]
            url = "https://b:9080"
            "#,
        )
        .unwrap();
        let specs = sources(
            &cfg,
            Flags {
                nodes: &[],
                token: Some("fallback"),
            },
        )
        .unwrap();
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].token.as_deref(), Some("t"));
        assert_eq!(specs[1].token.as_deref(), Some("fallback"));
        assert_eq!(specs[1].name, "b");
    }
}
