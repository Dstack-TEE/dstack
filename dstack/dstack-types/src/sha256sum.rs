// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Parser for `sha256sum.txt`, the file whose digest is `os_image_hash`.
//!
//! The file is the only thing binding `os_image_hash` to the bytes that get
//! measured, so every consumer must read it exactly the same way. We generate
//! it ourselves with `sha256sum <files>` (`os/image/assemble.sh`), so only that
//! output shape is accepted: one `<lowercase sha256>  <name>\n` line per file.
//! Everything else GNU `sha256sum` understands -- binary-mode `*name`,
//! `\`-escaped lines, paths -- is rejected rather than interpreted.

/// One `sha256sum.txt` entry: a file name and the digest it is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub hash: [u8; 32],
    pub name: String,
}

pub fn parse(checksum_file: &[u8]) -> Result<Vec<Entry>, String> {
    let body = std::str::from_utf8(checksum_file)
        .ok()
        .and_then(|text| text.strip_suffix('\n'))
        .ok_or("sha256sum.txt is not newline-terminated text")?;
    let mut entries: Vec<Entry> = Vec::new();
    for (index, line) in body.split('\n').enumerate() {
        let line_no = index + 1;
        let entry = parse_line(line).ok_or_else(|| {
            format!("sha256sum.txt line {line_no} is not `<lowercase sha256>  <file name>`")
        })?;
        if entries.iter().any(|e| e.name == entry.name) {
            return Err(format!(
                "sha256sum.txt line {line_no} repeats {}",
                entry.name
            ));
        }
        entries.push(entry);
    }
    Ok(entries)
}

pub fn entry_hash(checksum_file: &[u8], filename: &str) -> Result<[u8; 32], String> {
    parse(checksum_file)?
        .into_iter()
        .find(|entry| entry.name == filename)
        .map(|entry| entry.hash)
        .ok_or_else(|| format!("sha256sum.txt is missing {filename}"))
}

fn parse_line(line: &str) -> Option<Entry> {
    let (hash_hex, name) = line.split_once("  ")?;
    if !hash_hex
        .bytes()
        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        || !is_valid_name(name)
    {
        return None;
    }
    let mut hash = [0; 32];
    hex::decode_to_slice(hash_hex, &mut hash).ok()?;
    Some(Entry {
        hash,
        name: name.into(),
    })
}

/// A file in the image root, e.g. `bzImage` or `measurement.tdx.cbor`. The
/// manifest cannot list itself: its digest is the image identity.
fn is_valid_name(name: &str) -> bool {
    name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && name != "sha256sum.txt"
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn accepts_sha256sum_output() {
        let names = [
            "ovmf.fd",
            "bzImage",
            "initramfs.cpio.gz",
            "metadata.json",
            "measurement.aws.replay.json",
            "rootfs_v2-x86",
        ];
        let doc: String = names.iter().map(|n| format!("{DIGEST}  {n}\n")).collect();
        let entries = parse(doc.as_bytes()).unwrap();
        assert_eq!(
            entries.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
            names
        );
        assert_eq!(hex::encode(entries[0].hash), DIGEST);
        assert_eq!(entry_hash(doc.as_bytes(), "bzImage"), Ok(entries[1].hash));
        assert!(entry_hash(doc.as_bytes(), "missing").is_err());
    }

    #[test]
    fn rejects_anything_else() {
        let upper = DIGEST.to_uppercase();
        for doc in [
            String::new(),
            "\n".into(),
            format!("{DIGEST}  bzImage"),
            format!("{DIGEST}  bzImage\n\n"),
            format!("\n{DIGEST}  bzImage\n"),
            format!("{DIGEST}  bzImage\r\n"),
            format!("{DIGEST}  bzImage\n{DIGEST}  bzImage\n"),
            format!("{upper}  bzImage\n"),
            format!("{}  bzImage\n", &DIGEST[2..]),
            format!("{DIGEST}00  bzImage\n"),
            format!("{DIGEST} bzImage\n"),
            format!("{DIGEST} *bzImage\n"),
            format!("\\{DIGEST}  bzImage\n"),
            format!("{DIGEST}   bzImage\n"),
            format!("{DIGEST}  bzImage  junk\n"),
            format!("{DIGEST}  bz Image\n"),
            format!("{DIGEST}  \n"),
            format!("{DIGEST}  ./bzImage\n"),
            format!("{DIGEST}  ../bzImage\n"),
            format!("{DIGEST}  sub/bzImage\n"),
            format!("{DIGEST}  /bzImage\n"),
            format!("{DIGEST}  .\n"),
            format!("{DIGEST}  ..\n"),
            format!("{DIGEST}  .hidden\n"),
            format!("{DIGEST}  -rf\n"),
            format!("{DIGEST}  bz*Image\n"),
            format!("{DIGEST}  bzImage\u{200b}\n"),
            format!("{DIGEST}  sha256sum.txt\n"),
        ] {
            assert!(parse(doc.as_bytes()).is_err(), "accepted {doc:?}");
        }
        assert!(parse(b"\xff\n").is_err());
    }
}
