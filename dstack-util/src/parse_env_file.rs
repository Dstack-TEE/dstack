// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use tracing::warn;

/// Escape a value for systemd's `EnvironmentFile=` parser. A newline cannot be
/// represented there, so it is written as a literal `\n`.
fn escape_value(v: &str) -> String {
    let needs_quotes = v.contains(|c: char| c.is_whitespace() || r#"|&;<>()$`\"'"#.contains(c));
    let mut escaped = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\n' => escaped.push_str(r"\n"),
            '\\' | '"' | '$' | '`' => {
                escaped.push('\\');
                escaped.push(c);
            }
            _ => escaped.push(c),
        }
    }
    if needs_quotes {
        format!(r#""{escaped}""#)
    } else {
        escaped
    }
}

#[derive(Debug, Clone, Deserialize)]
struct Pair {
    key: String,
    value: String,
}

#[derive(Debug, Clone, Deserialize)]
struct Data {
    env: Vec<Pair>,
}

pub fn parse_env(env_json: &[u8], allowed: &BTreeSet<String>) -> Result<BTreeMap<String, String>> {
    const MAX_ITEMS: usize = 1024;
    const MAX_TOTAL_SIZE: usize = 1024 * 1024;

    let data: Data = serde_json::from_slice(env_json).context("Failed to parse env")?;

    if data.env.len() > MAX_ITEMS {
        bail!("Too many environment variables: {}", data.env.len());
    }

    const KEY_REGEX: &str = r"^[a-zA-Z_][a-zA-Z0-9_]*$";
    let key_regex = regex::Regex::new(KEY_REGEX)
        .context("Failed to compile environment key validation regex")?;

    let mut env = BTreeMap::new();
    let mut total_size = 0;

    for Pair { key, value } in data.env {
        if !allowed.contains(&key) {
            warn!("Skipping unauthorized environment variable: {key}");
            continue;
        }
        // Check key length (common Linux limit is 255)
        if key.len() > 255 {
            bail!("Environment variable name too long: {}", key);
        }

        // Check value length (common Linux limit is around 128KB)
        if value.len() > 128 * 1024 {
            bail!("Environment variable value too long for key: {}", key);
        }

        // validate key
        if !key_regex.is_match(&key) {
            bail!("Invalid env key: {}", key);
        }

        total_size += key.len() + value.len();
        if total_size > MAX_TOTAL_SIZE {
            bail!("Environment variables total size too large");
        }
        env.insert(key, value);
    }
    Ok(env)
}

pub fn convert_env_to_str(parsed_env: &BTreeMap<String, String>) -> String {
    #[allow(clippy::format_collect)]
    parsed_env
        .iter()
        .map(|(key, value)| {
            if value.contains('\n') {
                warn!("env var {key} contains a newline, delivering it as a literal \\n");
            }
            format!("{}={}\n", key, escape_value(value))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_value() {
        assert_eq!(escape_value("simple"), "simple");
        assert_eq!(escape_value("hello world"), r#""hello world""#);
        assert_eq!(escape_value(r#"say "hello""#), r#""say \"hello\"""#);
        assert_eq!(escape_value("line1\nline2"), r#""line1\nline2""#);
        assert_eq!(escape_value("price=$100"), r#""price=\$100""#);
        assert_eq!(escape_value("command=`date`"), r#""command=\`date\`""#);
        assert_eq!(escape_value(r"trail\"), r#""trail\\""#);
        assert_eq!(escape_value("cr\r"), "\"cr\r\"");
    }

    /// Round-trip through systemd's own parser; skipped without a user manager.
    #[test]
    fn systemd_round_trip() {
        use std::process::Command;

        let user_manager = Command::new("systemctl")
            .args(["--user", "show-environment"])
            .output()
            .is_ok_and(|o| o.status.success());
        if !user_manager {
            eprintln!("skipping: no systemd user manager");
            return;
        }
        let cases = [
            "",
            "a b",
            "tab\there",
            r#"say "hi""#,
            "$HOME",
            "`date`",
            r"back\slash",
            r"trail\",
            r"\",
            r#"a\"b"#,
            r"a\$b",
            r"a\`b",
            r"literal\n",
            "cr\rlf",
            "it's",
            "a;b|c&d",
            "#x",
            "ünï",
        ];
        let env: BTreeMap<_, _> = cases
            .iter()
            .enumerate()
            .map(|(i, v)| (format!("DSTACK_ENV_CASE_{i}"), v.to_string()))
            .collect();
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let file = dir.path().join("env");
        std::fs::write(&file, convert_env_to_str(&env)).expect("failed to write env file");
        let output = Command::new("systemd-run")
            .args(["--user", "--wait", "--collect", "--quiet", "--pipe"])
            .arg(format!("--property=EnvironmentFile={}", file.display()))
            .args(["env", "-0"])
            .output()
            .expect("failed to run systemd-run");
        assert!(output.status.success(), "systemd-run failed");
        let stdout = String::from_utf8(output.stdout).expect("env output is not utf-8");
        let delivered: BTreeMap<_, _> = stdout
            .split('\0')
            .filter_map(|kv| kv.split_once('='))
            .collect();
        for (key, value) in &env {
            assert_eq!(delivered.get(key.as_str()), Some(&value.as_str()), "{key}");
        }
    }
}
