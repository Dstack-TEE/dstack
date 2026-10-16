// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Text helpers that measure by display width, so CJK names and emoji keep
//! columns aligned.

use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

pub fn width(s: &str) -> usize {
    UnicodeWidthStr::width(s)
}

/// At most `max` columns of `s`, ending in "…" when cut.
pub fn truncate(s: &str, max: usize) -> String {
    if width(s) <= max {
        return s.to_string();
    }
    if max == 0 {
        return String::new();
    }
    let mut out = String::new();
    let mut used = 0;
    for c in s.chars() {
        let w = c.width().unwrap_or(0);
        if used + w > max - 1 {
            break;
        }
        used += w;
        out.push(c);
    }
    out.push('…');
    out
}

/// `s` cut or padded with spaces to exactly `w` columns.
pub fn pad(s: &str, w: usize) -> String {
    let t = truncate(s, w);
    let tw = width(&t);
    format!("{t}{}", " ".repeat(w.saturating_sub(tw)))
}

/// A log line made safe to draw: ANSI escape sequences removed (they would
/// move the cursor or recolor the screen), tabs expanded, other control
/// characters dropped.
pub fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\x1b' => match chars.peek() {
                // CSI: parameters up to a final byte in @..~.
                Some('[') => {
                    chars.next();
                    for c in chars.by_ref() {
                        if ('@'..='~').contains(&c) {
                            break;
                        }
                    }
                }
                // OSC: up to BEL or ST.
                Some(']') => {
                    chars.next();
                    while let Some(c) = chars.next() {
                        if c == '\x07' || (c == '\x1b' && chars.next_if_eq(&'\\').is_some()) {
                            break;
                        }
                    }
                }
                _ => {
                    chars.next();
                }
            },
            '\t' => out.push_str("    "),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

/// Two most significant units: `42s`, `5m09s`, `3h12m`, `2d04h`.
pub fn duration(secs: u64) -> String {
    let (d, h, m, s) = (
        secs / 86400,
        secs % 86400 / 3600,
        secs % 3600 / 60,
        secs % 60,
    );
    if d > 0 {
        format!("{d}d{h:02}h")
    } else if h > 0 {
        format!("{h}h{m:02}m")
    } else if m > 0 {
        format!("{m}m{s:02}s")
    } else {
        format!("{s}s")
    }
}

/// `512M`, `8G`, `1.5T` from megabytes.
pub fn mem_mb(mb: u64) -> String {
    if mb >= 1024 * 1024 {
        trim_float(mb as f64 / (1024.0 * 1024.0), "T")
    } else if mb >= 1024 {
        trim_float(mb as f64 / 1024.0, "G")
    } else {
        format!("{mb}M")
    }
}

/// `40G`, `1.2T` from gigabytes.
pub fn disk_gb(gb: u64) -> String {
    if gb >= 1024 {
        trim_float(gb as f64 / 1024.0, "T")
    } else {
        format!("{gb}G")
    }
}

fn trim_float(v: f64, unit: &str) -> String {
    if v >= 100.0 || (v - v.round()).abs() < 0.05 {
        format!("{:.0}{unit}", v)
    } else {
        format!("{:.1}{unit}", v)
    }
}

/// `3s ago`, `5m ago`, from two unix-ms instants.
pub fn ago(now_ms: u64, then_ms: u64) -> String {
    let secs = now_ms.saturating_sub(then_ms) / 1000;
    let d = duration(secs);
    // Only the leading unit reads well in a sentence.
    let lead: String = d
        .chars()
        .scan(false, |seen_unit, c| {
            if *seen_unit && c.is_ascii_digit() {
                return None;
            }
            if c.is_ascii_alphabetic() {
                *seen_unit = true;
            }
            Some(c)
        })
        .collect();
    format!("{lead} ago")
}

/// Local wall clock `HH:MM:SS` of a unix-ms instant.
pub fn clock(ms: u64) -> String {
    use chrono::{Local, TimeZone};
    match Local.timestamp_millis_opt(ms as i64) {
        chrono::LocalResult::Single(t) => t.format("%H:%M:%S").to_string(),
        _ => "--:--:--".into(),
    }
}

/// Local `MM-DD HH:MM:SS` of a unix-ms instant.
pub fn stamp(ms: u64) -> String {
    use chrono::{Local, TimeZone};
    match Local.timestamp_millis_opt(ms as i64) {
        chrono::LocalResult::Single(t) => t.format("%m-%d %H:%M:%S").to_string(),
        _ => "--".into(),
    }
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_by_width() {
        assert_eq!(truncate("hello", 5), "hello");
        assert_eq!(truncate("hello world", 6), "hello…");
        assert_eq!(truncate("名字很长的", 5), "名字…");
        assert_eq!(width(&pad("名字", 6)), 6);
    }

    #[test]
    fn durations_keep_two_units() {
        assert_eq!(duration(42), "42s");
        assert_eq!(duration(309), "5m09s");
        assert_eq!(duration(3 * 3600 + 12 * 60 + 5), "3h12m");
        assert_eq!(duration(2 * 86400 + 4 * 3600), "2d04h");
        assert_eq!(ago(10_000, 5_000), "5s ago");
        assert_eq!(ago(400_000, 0), "6m ago");
    }

    #[test]
    fn sizes_are_compact() {
        assert_eq!(mem_mb(512), "512M");
        assert_eq!(mem_mb(2048), "2G");
        assert_eq!(mem_mb(1536), "1.5G");
        assert_eq!(mem_mb(1024 * 1024 * 3 / 2), "1.5T");
        assert_eq!(disk_gb(40), "40G");
        assert_eq!(disk_gb(2048), "2T");
    }

    #[test]
    fn sanitize_strips_cursor_movement() {
        assert_eq!(sanitize("a\x1b[2Kb\tc\r"), "ab    c");
        assert_eq!(sanitize("\x1b[1;32mok\x1b[0m done"), "ok done");
        assert_eq!(sanitize("\x1b]0;title\x07x\x1b]8;;u\x1b\\y"), "xy");
    }
}
