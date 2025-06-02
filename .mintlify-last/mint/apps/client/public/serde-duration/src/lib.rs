use serde::{Deserialize, Deserializer, Serializer};
use std::time::Duration;

pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if duration == &Duration::MAX {
        return serializer.serialize_str("never");
    }
    let (value, unit) = if duration.as_secs() % (24 * 3600) == 0 {
        (duration.as_secs() / (24 * 3600), "d")
    } else if duration.as_secs() % 3600 == 0 {
        (duration.as_secs() / 3600, "h")
    } else if duration.as_secs() % 60 == 0 {
        (duration.as_secs() / 60, "m")
    } else {
        (duration.as_secs(), "s")
    };
    serializer.serialize_str(&format!("{}{}", value, unit))
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if s.is_empty() {
        return Err(serde::de::Error::custom("Duration string cannot be empty"));
    }
    if s == "never" {
        return Ok(Duration::MAX);
    }
    let (value, unit) = s.split_at(s.len() - 1);
    let value = value.parse::<u64>().map_err(serde::de::Error::custom)?;

    let seconds = match unit {
        "s" => value,
        "m" => value * 60,
        "h" => value * 3600,
        "d" => value * 24 * 3600,
        _ => {
            return Err(serde::de::Error::custom(
                "Invalid time unit. Use s, m, h, or d",
            ))
        }
    };

    Ok(Duration::from_secs(seconds))
}
