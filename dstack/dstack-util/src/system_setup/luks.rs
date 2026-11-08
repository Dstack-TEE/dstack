// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! LUKS2 header validation and key epoch migration.
//! Fields validation does not inspect are not modeled; serde ignores them.
//! See <https://gitlab.com/cryptsetup/LUKS2-docs/blob/main/luks2_doc_wip.pdf>.

use std::{
    collections::HashMap,
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

use anyhow::{bail, Context, Result};
use fs_err as fs;
use safe_write::safe_write_with_mode;
use scopeguard::defer;
use serde::{de::IgnoredAny, Deserialize};
use serde_with::{serde_as, DisplayFromStr};

/// Size of the binary header that precedes each JSON area.
const BINARY_HEADER_SIZE: u64 = 4096;

struct LuksHeader {
    pub magic: [u8; 6],
    pub version: u16,
    pub hdr_size: u64,
    pub label: [u8; 48],
    pub csum_alg: [u8; 32],
    pub subsystem: [u8; 48],
    pub hdr_offset: u64,
}

impl LuksHeader {
    /// Decodes the big-endian binary header.
    pub fn parse(data: &[u8]) -> Result<Self> {
        fn field<const N: usize>(data: &[u8], offset: usize) -> Result<[u8; N]> {
            let bytes = data
                .get(offset..offset + N)
                .context("LUKS header is truncated")?;
            Ok(bytes.try_into()?)
        }
        Ok(Self {
            magic: field(data, 0)?,
            version: u16::from_be_bytes(field(data, 6)?),
            hdr_size: u64::from_be_bytes(field(data, 8)?),
            label: field(data, 24)?,
            csum_alg: field(data, 72)?,
            subsystem: field(data, 208)?,
            hdr_offset: u64::from_be_bytes(field(data, 256)?),
        })
    }
}

#[derive(Deserialize)]
struct LuksJson {
    pub keyslots: HashMap<u8, LuksKeyslot>,
    pub tokens: HashMap<u8, LuksToken>,
    pub segments: HashMap<u8, LuksSegment>,
    pub digests: HashMap<u8, LuksDigest>,
    pub config: LuksConfig,
}

/// Type of the only token dstack writes: the KMS key epoch of keyslot 0.
const ROOT_EPOCH_TOKEN_TYPE: &str = "dstack-kms";

#[derive(Deserialize)]
struct LuksToken {
    #[serde(rename = "type")]
    pub kind: String,
    pub keyslots: Vec<String>,
    #[serde(default)]
    pub root_epoch: Option<u32>,
    #[serde(default)]
    pub app_epoch: u32,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum LuksKeyslot {
    Luks2 {
        key_size: u16,
        area: LuksArea,
        kdf: LuksKdf,
        af: LuksAf,
        #[serde(default)]
        priority: Option<IgnoredAny>,
    },
}

#[serde_as]
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum LuksArea {
    Raw {
        encryption: String,
        key_size: u32,
        #[serde_as(as = "DisplayFromStr")]
        offset: u64,
        #[serde_as(as = "DisplayFromStr")]
        size: u64,
    },
}

/// Salt and iterations are left unchecked on purpose: the passphrase is
/// high-entropy and KMS-derived, so attacker-chosen values buy nothing without
/// it (see security report #552).
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum LuksKdf {
    Pbkdf2 {
        hash: String,
    },
    #[serde(other)]
    Unsupported,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum LuksAf {
    Luks1 { hash: String, stripes: u16 },
}

#[serde_as]
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum LuksSegment {
    Crypt {
        #[serde_as(as = "DisplayFromStr")]
        offset: u64,
        size: String,
        #[serde_as(as = "DisplayFromStr")]
        iv_tweak: u64,
        encryption: String,
        sector_size: u16,
        #[serde(default)]
        integrity: Option<IgnoredAny>,
        #[serde(default)]
        flags: Option<IgnoredAny>,
    },
}

#[serde_as]
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum LuksDigest {
    Pbkdf2 {
        #[serde_as(as = "Vec<DisplayFromStr>")]
        keyslots: Vec<u8>,
        #[serde_as(as = "Vec<DisplayFromStr>")]
        segments: Vec<u8>,
        hash: String,
    },
}

#[serde_as]
#[derive(Deserialize)]
struct LuksConfig {
    #[serde_as(as = "DisplayFromStr")]
    pub keyslots_size: u64,
    #[serde(default)]
    pub flags: Option<IgnoredAny>,
    #[serde(default)]
    pub requirements: Option<IgnoredAny>,
}

macro_rules! const_pad {
    ($s:expr, $len:expr) => {
        const {
            assert!($s.len() <= $len, "The s is too long");
            let mut padded: [u8; $len] = [0; $len];
            let mut i = 0;
            while i < $s.len() {
                padded[i] = $s[i];
                i += 1;
            }
            padded
        }
    };
}

pub(super) const PAYLOAD_OFFSET: u64 = 16777216;

fn cryptsetup(args: &[&str], device: &Path) -> Command {
    let mut command = Command::new("cryptsetup");
    command.args(args).arg(device);
    command
}

/// Run `command` with `input` on stdin and return its exit code.
fn run_with_input(mut command: Command, input: &[u8]) -> Result<Option<i32>> {
    let mut child = command
        .stdin(Stdio::piped())
        .spawn()
        .context("failed to start cryptsetup")?;
    child
        .stdin
        .take()
        .context("cryptsetup stdin is unavailable")?
        .write_all(input)
        .context("failed to write to cryptsetup")?;
    Ok(child
        .wait()
        .context("failed to wait for cryptsetup")?
        .code())
}

pub(super) fn write_luks_epochs(device: &Path, epoch: u32, app_epoch: u32) -> Result<()> {
    let token = serde_json::json!({
        "type": ROOT_EPOCH_TOKEN_TYPE,
        "keyslots": ["0"],
        "root_epoch": epoch,
        "app_epoch": app_epoch,
    });
    let args = ["token", "import", "--token-id", "0", "--token-replace"];
    let code = run_with_input(cryptsetup(&args, device), token.to_string().as_bytes())?;
    if code != Some(0) {
        bail!("failed to record root epoch {epoch} in the LUKS header: {code:?}");
    }
    Ok(())
}

/// Replace the keyslot 0 passphrase of a detached LUKS `header` and record
/// `epoch` in it. The new key goes over stdin; the old one is written next to
/// the header, which must be in a private in-memory directory.
pub(super) fn rekey_luks_header_at_epochs(
    header: &Path,
    old_key: &str,
    new_key: &str,
    epoch: u32,
    app_epoch: u32,
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    // luksHeaderBackup leaves the copy read-only.
    fs::set_permissions(header, std::fs::Permissions::from_mode(0o600))?;
    let old_file = header.with_file_name("old-key");
    defer! {
        fs::remove_file(&old_file).ok();
    }
    safe_write_with_mode(&old_file, old_key, 0o600)?;
    let mut command = cryptsetup(
        &[
            "luksChangeKey",
            "--batch-mode",
            "--pbkdf",
            "pbkdf2",
            "--key-slot",
            "0",
        ],
        header,
    );
    command.arg("--key-file").arg(&old_file);
    if run_with_input(command, new_key.as_bytes())? != Some(0) {
        bail!("cryptsetup luksChangeKey failed");
    }
    write_luks_epochs(header, epoch, app_epoch)
}

#[cfg(test)]
fn write_luks_root_epoch(device: &Path, epoch: u32) -> Result<()> {
    write_luks_epochs(device, epoch, 0)
}

#[cfg(test)]
fn rekey_luks_header(header: &Path, old_key: &str, new_key: &str, epoch: u32) -> Result<()> {
    rekey_luks_header_at_epochs(header, old_key, new_key, epoch, 0)
}

/// Set by luksFormat and cleared once the filesystem exists, so a disk still
/// carrying it was interrupted mid-initialization and holds no data.
pub(super) const LUKS_INITIALIZING_LABEL: &str = "dstack-initializing";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct LuksHeaderState {
    /// The header carries [`LUKS_INITIALIZING_LABEL`].
    pub(super) initializing: bool,
    /// Root epoch recorded in the dstack token; `None` means epoch 0.
    pub(super) root_epoch: Option<u32>,
    pub(super) app_epoch: u32,
}

pub(super) fn validate_luks2_headers(mut reader: impl std::io::Read) -> Result<LuksHeaderState> {
    let primary = validate_single_luks2_header(&mut reader, 0)?;
    let secondary = validate_single_luks2_header(&mut reader, 1)?;
    if primary.root_epoch != secondary.root_epoch || primary.app_epoch != secondary.app_epoch {
        bail!("LUKS header copies disagree on the key epoch");
    }
    Ok(primary)
}

fn validate_single_luks2_header(
    mut reader: impl std::io::Read,
    hdr_ind: u64,
) -> Result<LuksHeaderState> {
    let mut hdr_data = vec![0u8; BINARY_HEADER_SIZE as usize];
    reader
        .read_exact(&mut hdr_data)
        .context("Failed to read LUKS header")?;
    let LuksHeader {
        magic,
        version,
        hdr_size,
        label,
        csum_alg,
        subsystem,
        hdr_offset,
    } = LuksHeader::parse(&hdr_data).context("Failed to decode LUKS header")?;

    let expected_magic = match hdr_ind {
        0 => [76, 85, 75, 83, 186, 190],
        1 => [83, 75, 85, 76, 186, 190],
        _ => bail!("Invalid LUKS header index: {hdr_ind}"),
    };
    if magic != expected_magic {
        bail!("Invalid LUKS magic: {magic:?}");
    }
    if version != 2 {
        bail!("Invalid LUKS version: {version}");
    }
    let initializing = label == const_pad!(LUKS_INITIALIZING_LABEL.as_bytes(), 48);
    if !initializing && label != [0; 48] {
        bail!("Invalid LUKS label: {:?}", label);
    }
    if csum_alg != const_pad!(b"sha256", 32) {
        bail!("Invalid LUKS checksum algorithm");
    }
    if subsystem != [0; 48] {
        bail!("Invalid LUKS subsystem");
    }
    if hdr_offset != hdr_ind * hdr_size {
        bail!("Invalid LUKS header offset: {hdr_offset}");
    }
    if !(4096..=1024 * 1024 * 16).contains(&hdr_size) {
        bail!("Invalid LUKS header size: {hdr_size}");
    }

    // Check JSON
    let json_size = hdr_size - BINARY_HEADER_SIZE;
    let mut jsn_data = vec![0u8; json_size as usize];
    reader
        .read_exact(&mut jsn_data)
        .context("Failed to read LUKS JSON")?;
    let json_end = jsn_data
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(jsn_data.len());
    jsn_data.truncate(json_end);

    let LuksJson {
        keyslots,
        tokens,
        segments,
        digests,
        config:
            LuksConfig {
                keyslots_size,
                flags,
                requirements,
            },
    } = serde_json::from_slice(&jsn_data).context("Failed to decode LUKS JSON")?;

    if keyslots.len() != 1 {
        bail!("Invalid LUKS keyslots");
    }
    let root_epoch = match tokens.len() {
        0 => None,
        1 => {
            let token = tokens.get(&0).context("Invalid LUKS token id")?;
            if token.kind != ROOT_EPOCH_TOKEN_TYPE || token.keyslots != ["0"] {
                bail!("Invalid LUKS token");
            }
            Some(token.root_epoch.context("LUKS token has no root epoch")?)
        }
        _ => bail!("Invalid LUKS tokens"),
    };
    if segments.len() != 1 {
        bail!("Invalid LUKS segments");
    }
    if digests.len() != 1 {
        bail!("Invalid LUKS digests");
    }
    if keyslots_size % 4096 != 0 {
        bail!("Invalid LUKS keyslots size: {keyslots_size}");
    }
    if flags.is_some() {
        bail!("Invalid LUKS flags");
    }
    if requirements.is_some() {
        bail!("Invalid LUKS requirements");
    }

    {
        let LuksKeyslot::Luks2 {
            key_size,
            area:
                LuksArea::Raw {
                    encryption,
                    key_size: area_key_size,
                    offset,
                    size,
                },
            kdf,
            af:
                LuksAf::Luks1 {
                    hash: af_hash,
                    stripes,
                },
            priority,
        } = keyslots.get(&0).context("no LUKS keyslot")?;
        if encryption != "aes-xts-plain64" {
            bail!("Invalid LUKS keyslot encryption: {encryption}");
        }
        // Pin where the encrypted key material is read from. The binary area
        // must sit between the two header copies and the encrypted payload;
        // otherwise a host with raw disk access could redirect it elsewhere.
        let area_end = offset.checked_add(*size);
        if *offset < 2 * hdr_size || area_end.is_none_or(|end| end > PAYLOAD_OFFSET) {
            bail!("Invalid LUKS keyslot area: offset={offset} size={size}");
        }
        if *key_size != 64 {
            bail!("Invalid LUKS keyslot key size: {key_size}");
        }
        if *area_key_size != 64 {
            bail!("Invalid LUKS keyslot key size: {area_key_size}");
        }
        let LuksKdf::Pbkdf2 { hash: kdf_hash } = kdf else {
            bail!("Invalid LUKS keyslot KDF");
        };
        if kdf_hash != "sha256" {
            bail!("Invalid LUKS keyslot hash: {kdf_hash}");
        }
        if af_hash != "sha256" {
            bail!("Invalid LUKS keyslot hash: {af_hash}");
        }
        if *stripes != 4000 {
            bail!("Invalid LUKS keyslot stripes: {stripes}");
        }
        if priority.is_some() {
            bail!("Invalid LUKS keyslot priority");
        }
    }

    {
        let LuksSegment::Crypt {
            offset,
            size,
            iv_tweak,
            encryption,
            sector_size,
            integrity,
            flags,
        } = segments.get(&0).context("no LUKS segment")?;
        if *offset != PAYLOAD_OFFSET {
            bail!("Invalid LUKS segment offset");
        }
        if size != "dynamic" {
            bail!("Invalid LUKS segment size");
        }
        if *iv_tweak != 0 {
            bail!("Invalid LUKS segment IV tweak");
        }
        if encryption != "aes-xts-plain64" {
            bail!("Invalid LUKS segment encryption");
        }
        if *sector_size != 512 {
            bail!("Invalid LUKS segment sector size");
        }
        if integrity.is_some() {
            bail!("Invalid LUKS segment integrity");
        }
        if flags.is_some() {
            bail!("Invalid LUKS segment flags");
        }
    }
    {
        let LuksDigest::Pbkdf2 {
            keyslots,
            segments,
            hash,
        } = digests.get(&0).context("no LUKS digest")?;
        if hash != "sha256" {
            bail!("Invalid LUKS digest hash: {hash}");
        }
        if keyslots != &[0] {
            bail!("Invalid LUKS digest keyslots: {keyslots:?}");
        }
        if segments != &[0] {
            bail!("Invalid LUKS digest segments: {segments:?}");
        }
    }
    Ok(LuksHeaderState {
        initializing,
        root_epoch,
        app_epoch: tokens.get(&0).map(|token| token.app_epoch).unwrap_or(0),
    })
}

#[test]
fn test_validate_luks2_header() {
    let mut header_data = include_bytes!("../../tests/fixtures/luks_header_good").to_vec();
    let state =
        validate_luks2_headers(&mut &header_data[..]).expect("Failed to validate LUKS2 header");
    assert_eq!(
        state,
        LuksHeaderState {
            initializing: false,
            root_epoch: None,
            app_epoch: 0
        }
    );
    header_data[24..24 + LUKS_INITIALIZING_LABEL.len()]
        .copy_from_slice(LUKS_INITIALIZING_LABEL.as_bytes());
    assert!(
        validate_luks2_headers(&mut &header_data[..])
            .expect("Failed to validate LUKS2 header")
            .initializing
    );
    let header_data = include_bytes!("../../tests/fixtures/luks_header_cipher_null").to_vec();
    let error = validate_luks2_headers(&mut &header_data[..]).unwrap_err();
    assert!(error
        .to_string()
        .contains("Invalid LUKS keyslot encryption"));
}

#[test]
fn test_validate_luks2_header_rejects_out_of_range_keyslot_area() {
    // Redirect the keyslot binary area below the header region. Same length
    // so the surrounding header stays intact; "00768" parses to 768, which is
    // inside the header copies (< 2 * hdr_size) rather than the metadata gap.
    let mut header = include_bytes!("../../tests/fixtures/luks_header_good").to_vec();
    let patched = patch_luks_json(&mut header, br#""offset":"32768""#, br#""offset":"00768""#);
    assert_eq!(patched, 2, "expected to patch both header copies");
    let error = validate_luks2_headers(&mut &header[..]).unwrap_err();
    assert!(error.to_string().contains("Invalid LUKS keyslot area"));
}

/// Replace `needle` with `replacement` inside every LUKS JSON region, keeping
/// each region the same length by giving back trailing NUL padding.
#[cfg(test)]
fn patch_luks_json(header: &mut [u8], needle: &[u8], replacement: &[u8]) -> usize {
    assert!(replacement.len() >= needle.len());
    let grow = replacement.len() - needle.len();
    let mut patched = 0;
    let mut i = 0;
    while i + needle.len() <= header.len() {
        if &header[i..i + needle.len()] != needle {
            i += 1;
            continue;
        }
        let tail = &mut header[i..];
        let end = tail.iter().position(|b| *b == 0).expect("NUL padding");
        assert!(end + grow < tail.len(), "not enough NUL padding");
        tail.copy_within(needle.len()..end, replacement.len());
        tail[..replacement.len()].copy_from_slice(replacement);
        patched += 1;
        i += replacement.len();
    }
    patched
}

#[test]
fn test_disk_key_migration_with_cryptsetup() {
    if Command::new("cryptsetup")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("cryptsetup is unavailable; skipping");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("disk.img");
    fs::File::create(&image)
        .unwrap()
        .set_len(2 * PAYLOAD_OFFSET)
        .unwrap();
    let offset = (PAYLOAD_OFFSET / 512).to_string();
    let format = cryptsetup(
        &[
            "luksFormat",
            "--batch-mode",
            "--type",
            "luks2",
            "--offset",
            &offset,
            "--cipher",
            "aes-xts-plain64",
            "--pbkdf",
            "pbkdf2",
            "--sector-size",
            "512",
            "-d-",
        ],
        &image,
    );
    assert_eq!(run_with_input(format, b"old").unwrap(), Some(0));
    let unlocks = |key: &str| {
        let test = cryptsetup(
            &["open", "--test-passphrase", "--key-slot", "0", "-d-"],
            &image,
        );
        run_with_input(test, key.as_bytes()).unwrap() == Some(0)
    };

    // Re-key a detached copy of the header, as the boot does, and restore it.
    let header = dir.path().join("header");
    let backup = cryptsetup(&["luksHeaderBackup", "--header-backup-file"], &header)
        .arg(&image)
        .status()
        .unwrap();
    assert!(backup.success());
    rekey_luks_header(&header, "old", "new", 2).unwrap();
    assert!(!dir.path().join("old-key").exists());
    assert!(
        unlocks("old"),
        "the disk is unchanged until the header is restored"
    );
    let state = validate_luks2_headers(fs::File::open(&header).unwrap()).unwrap();
    assert_eq!(state.root_epoch, Some(2));

    let restore = cryptsetup(
        &["luksHeaderRestore", "--batch-mode", "--header-backup-file"],
        &header,
    )
    .arg(&image)
    .status()
    .unwrap();
    assert!(restore.success());
    assert!(unlocks("new"));
    assert!(!unlocks("old"));

    // A later rotation replaces the recorded epoch.
    write_luks_root_epoch(&image, 3).unwrap();
    fs::remove_file(&header).unwrap();
    let backup = cryptsetup(&["luksHeaderBackup", "--header-backup-file"], &header)
        .arg(&image)
        .status()
        .unwrap();
    assert!(backup.success());
    let state = validate_luks2_headers(fs::File::open(&header).unwrap()).unwrap();
    assert_eq!(state.root_epoch, Some(3));
    rekey_luks_header_at_epochs(&header, "new", "app-epoch-one", 3, 1).unwrap();
    let rotated = validate_luks2_headers(fs::File::open(&header).unwrap()).unwrap();
    assert_eq!(rotated.root_epoch, Some(3));
    assert_eq!(rotated.app_epoch, 1);
    assert!(cryptsetup(
        &["luksHeaderRestore", "--batch-mode", "--header-backup-file"],
        &header
    )
    .arg(&image)
    .status()
    .unwrap()
    .success());
    assert!(!unlocks("new"));
    assert!(unlocks("app-epoch-one"));
}

#[test]
fn test_validate_luks2_header_root_epoch_token() {
    let with_token = |token: &str| {
        let mut header = include_bytes!("../../tests/fixtures/luks_header_good").to_vec();
        let replacement = format!(r#""tokens":{{"0":{token}}}"#);
        let patched = patch_luks_json(&mut header, br#""tokens":{}"#, replacement.as_bytes());
        assert_eq!(patched, 2, "expected to patch both header copies");
        validate_luks2_headers(&mut &header[..])
    };
    let state = with_token(r#"{"type":"dstack-kms","keyslots":["0"],"root_epoch":2}"#).unwrap();
    assert_eq!(state.root_epoch, Some(2));
    for token in [
        r#"{"type":"luks2-keyring","keyslots":["0"],"root_epoch":2}"#,
        r#"{"type":"dstack-kms","keyslots":["1"],"root_epoch":2}"#,
        r#"{"type":"dstack-kms","keyslots":["0"]}"#,
    ] {
        assert!(with_token(token).is_err(), "{token}");
    }
}

#[test]
fn test_validate_luks2_header_rejects_keyslot_area_that_overflows() {
    let mut header = include_bytes!("../../tests/fixtures/luks_header_good").to_vec();
    // 2**64 - 32768 + 1000: added to the accepted offset 32768 it wraps to
    // 1000, which is below PAYLOAD_OFFSET.
    let patched = patch_luks_json(
        &mut header,
        br#""size":"258048""#,
        br#""size":"18446744073709519848""#,
    );
    assert_eq!(patched, 2, "expected to patch both header copies");
    let error = validate_luks2_headers(&mut &header[..]).unwrap_err();
    assert!(
        error.to_string().contains("Invalid LUKS keyslot area"),
        "{error:#}"
    );
}
