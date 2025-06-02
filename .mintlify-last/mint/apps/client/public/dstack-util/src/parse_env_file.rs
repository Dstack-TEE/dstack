use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use tracing::warn;

fn escape_value(v: &str) -> String {
    let mut needs_quotes = false;
    let mut escaped = String::with_capacity(v.len());

    // Check if we need quotes (spaces or special chars)
    if v.chars().any(|c| " \t|&;<>()$`\\\"'\n".contains(c)) {
        needs_quotes = true;
    }

    // Escape special characters
    for c in v.chars() {
        match c {
            '\n' => escaped.push_str("\\n"),
            '"' => escaped.push_str("\\\""),
            '$' => escaped.push_str("\\$"),
            '`' => escaped.push_str("\\`"),
            _ => escaped.push(c),
        }
    }

    // Wrap in quotes if needed
    if needs_quotes {
        format!("\"{}\"", escaped)
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
        .map(|(key, value)| format!("{}={}\n", key, escape_value(value)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_value() {
        assert_eq!(escape_value("simple"), "simple");
        assert_eq!(escape_value("hello world"), "\"hello world\"");
        assert_eq!(escape_value("say \"hello\""), "\"say \\\"hello\\\"\"");
        assert_eq!(escape_value("line1\nline2"), "\"line1\\nline2\"");
        assert_eq!(escape_value("price=$100"), "\"price=\\$100\"");
        assert_eq!(escape_value("command=`date`"), "\"command=\\`date\\`\"");
    }
}
