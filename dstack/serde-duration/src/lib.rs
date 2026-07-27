// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Deserializer, Serializer};
use std::time::Duration;

/// Render a duration in the largest unit that divides it evenly.
fn format(duration: &Duration) -> String {
    if duration == &Duration::MAX {
        return "never".to_string();
    }
    let (value, unit) = if duration.as_secs().is_multiple_of(24 * 3600) {
        (duration.as_secs() / (24 * 3600), "d")
    } else if duration.as_secs().is_multiple_of(3600) {
        (duration.as_secs() / 3600, "h")
    } else if duration.as_secs().is_multiple_of(60) {
        (duration.as_secs() / 60, "m")
    } else {
        (duration.as_secs(), "s")
    };
    format!("{value}{unit}")
}

/// Parse a `<value><unit>` duration, or `never` for [`Duration::MAX`].
fn parse(s: &str) -> Result<Duration, String> {
    if s.is_empty() {
        return Err("Duration string cannot be empty".to_string());
    }
    if s == "never" {
        return Ok(Duration::MAX);
    }
    // Split on the last *character*, not the last byte: `split_at(len - 1)`
    // panics inside `core::str` when the unit is multi-byte, and a config file
    // is exactly the place where a typo should be reported, not panicked on.
    let unit_start = s
        .char_indices()
        .next_back()
        .map(|(i, _)| i)
        .ok_or_else(|| "Duration string cannot be empty".to_string())?;
    let (value, unit) = s.split_at(unit_start);
    let value = value.parse::<u64>().map_err(|e| e.to_string())?;

    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 24 * 3600,
        _ => return Err("Invalid time unit. Use s, m, h, or d".to_string()),
    };
    // Checked: `18446744073709551615d` would otherwise wrap to a short duration
    // in release builds, i.e. a timeout far tighter than the operator asked for.
    let seconds = value
        .checked_mul(multiplier)
        .ok_or_else(|| format!("Duration {s} is too large"))?;

    Ok(Duration::from_secs(seconds))
}

pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&format(duration))
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    parse(&s).map_err(serde::de::Error::custom)
}

/// `Option<Duration>` variant, for config fields where an absent value means
/// "this knob is not configured" rather than zero.
///
/// Prefer this over a sentinel (`0`, or the `never` string) whenever the field
/// is one of several independent gates: with a sentinel the same value has to
/// mean both "disabled" and a legitimate setting, which is exactly the
/// ambiguity that makes multi-gate configs hard to reason about.
pub mod option {
    use super::{format, parse};
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match duration {
            Some(duration) => serializer.serialize_str(&format(duration)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let Some(s) = Option::<String>::deserialize(deserializer)? else {
            return Ok(None);
        };
        parse(&s).map(Some).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Plain {
        #[serde(with = "crate")]
        d: Duration,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Opt {
        #[serde(default, with = "crate::option")]
        d: Option<Duration>,
    }

    #[test]
    fn parses_every_unit() {
        for (text, secs) in [("30s", 30), ("5m", 300), ("2h", 7200), ("1d", 86400)] {
            let v: Plain = serde_json::from_str(&format!(r#"{{"d":"{text}"}}"#)).unwrap();
            assert_eq!(v.d, Duration::from_secs(secs));
        }
        let v: Plain = serde_json::from_str(r#"{"d":"never"}"#).unwrap();
        assert_eq!(v.d, Duration::MAX);
    }

    #[test]
    fn rejects_bad_input() {
        for text in ["", "5x", "abcs"] {
            let parsed: Result<Plain, _> = serde_json::from_str(&format!(r#"{{"d":"{text}"}}"#));
            assert!(parsed.is_err(), "{text} should not parse");
        }
    }

    #[test]
    fn option_absent_is_none() {
        let v: Opt = serde_json::from_str("{}").unwrap();
        assert_eq!(v.d, None);
        let v: Opt = serde_json::from_str(r#"{"d":null}"#).unwrap();
        assert_eq!(v.d, None);
    }

    #[test]
    fn option_present_parses() {
        let v: Opt = serde_json::from_str(r#"{"d":"5s"}"#).unwrap();
        assert_eq!(v.d, Some(Duration::from_secs(5)));
    }

    #[test]
    fn round_trips() {
        let v = Opt {
            d: Some(Duration::from_secs(300)),
        };
        let text = serde_json::to_string(&v).unwrap();
        assert_eq!(text, r#"{"d":"5m"}"#);
        assert_eq!(serde_json::from_str::<Opt>(&text).unwrap(), v);
    }

    /// A bad unit is a config typo, so it has to come back as an error --
    /// including when the typo is not ASCII, where splitting on the last byte
    /// used to panic inside `core::str`.
    #[test]
    fn a_bad_unit_is_an_error_not_a_panic() {
        assert!(parse("5\u{5206}").is_err());
        assert!(parse("5x").is_err());
        assert!(parse("\u{5206}").is_err());
        assert!(parse("s").is_err());
    }

    /// Overflow would silently wrap to a much shorter timeout than asked for.
    #[test]
    fn an_oversized_duration_is_rejected() {
        assert!(parse(&format!("{}d", u64::MAX)).is_err());
        assert_eq!(parse("5m").unwrap(), Duration::from_secs(300));
    }
}
