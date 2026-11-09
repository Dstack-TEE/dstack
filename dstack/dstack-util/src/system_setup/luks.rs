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
use tracing::info;

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

/// Type of the only token dstack writes: the KMS key epochs of one keyslot.
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

/// Record that keyslot `slot` holds the key of `epoch` and `app_epoch`.
pub(super) fn write_luks_epochs(device: &Path, slot: u8, epoch: u32, app_epoch: u32) -> Result<()> {
    let token = serde_json::json!({
        "type": ROOT_EPOCH_TOKEN_TYPE,
        "keyslots": [slot.to_string()],
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

/// Back up the LUKS header of `device` to `header` and validate the copy.
pub(super) fn load_luks_header(device: &Path, header: &Path) -> Result<LuksHeaderState> {
    if header.exists() {
        fs::remove_file(header)?;
    }
    let status = Command::new("cryptsetup")
        .args(["luksHeaderBackup", "--header-backup-file"])
        .arg(header)
        .arg(device)
        .status()
        .context("failed to start cryptsetup luksHeaderBackup")?;
    if !status.success() {
        bail!("failed to back up the LUKS header");
    }
    validate_luks2_headers(fs::File::open(header)?).context("failed to validate the LUKS2 header")
}

/// The keyslot of the validated `header` that `key` unlocks.
fn unlocked_keyslot(header: &Path, state: &LuksHeaderState, key: &str) -> Result<Option<u8>> {
    for &slot in &state.keyslots {
        if unlocks(header, slot, key)? {
            return Ok(Some(slot));
        }
    }
    Ok(None)
}

/// Whether `key` unlocks keyslot `slot` of the validated `header`.
fn unlocks(header: &Path, slot: u8, key: &str) -> Result<bool> {
    let slot_arg = slot.to_string();
    let test = cryptsetup(
        &["open", "--test-passphrase", "--key-slot", &slot_arg, "-d-"],
        header,
    );
    match run_with_input(test, key.as_bytes())? {
        Some(0) => Ok(true),
        // No key available with this passphrase.
        Some(2) => Ok(false),
        code => bail!("failed to test the LUKS passphrase: {code:?}"),
    }
}

/// Add `new_key` in keyslot `slot`, authorized by `old_key`. The old key is
/// written next to `header`, which must be in a private in-memory directory.
fn add_luks_key(
    device: &Path,
    header: &Path,
    old_key: &str,
    new_key: &str,
    slot: u8,
) -> Result<()> {
    let old_file = header.with_file_name("old-key");
    defer! {
        fs::remove_file(&old_file).ok();
    }
    safe_write_with_mode(&old_file, old_key, 0o600)?;
    let slot = slot.to_string();
    let args = [
        "luksAddKey",
        "--batch-mode",
        "--pbkdf",
        "pbkdf2",
        "--new-key-slot",
        &slot,
    ];
    let mut command = cryptsetup(&args, device);
    command.arg("--key-file").arg(&old_file);
    if run_with_input(command, new_key.as_bytes())? != Some(0) {
        bail!("cryptsetup luksAddKey failed");
    }
    Ok(())
}

fn kill_luks_slot(device: &Path, slot: u8) -> Result<()> {
    let status = cryptsetup(&["luksKillSlot", "--batch-mode"], device)
        .arg(slot.to_string())
        .stdin(Stdio::null())
        .status()
        .context("failed to start cryptsetup luksKillSlot")?;
    if !status.success() {
        bail!("failed to remove LUKS keyslot {slot}");
    }
    Ok(())
}

/// Bring the data disk to the `target` epochs, so that `key` unlocks its only
/// keyslot and the token records `target`.
///
/// Each step is a single atomic LUKS2 metadata update: add the new key with
/// the old one, record the new epochs, then remove the old keyslot. Whatever
/// step a crash interrupts, the next boot finds either the old key alone or a
/// keyslot `key` already unlocks, and finishes from there. `old_key` is only
/// called when `key` unlocks no keyslot. An unrotated epoch-0 disk is left
/// untouched, so it stays readable by older OS images.
///
/// `header` holds the validated in-memory copy of `state` and is refreshed
/// after every change.
pub(super) async fn sync_luks_epochs<F, Fut>(
    device: &Path,
    header: &Path,
    mut state: LuksHeaderState,
    key: &str,
    target: (u32, u32),
    old_key: F,
) -> Result<LuksHeaderState>
where
    F: FnOnce(u32, u32) -> Fut,
    Fut: std::future::Future<Output = Result<String>>,
{
    let stored = (state.root_epoch.unwrap_or(0), state.app_epoch);
    if stored.0 > target.0 || stored.1 > target.1 {
        bail!("the data disk epochs {stored:?} exceed current {target:?}");
    }
    let slot = match unlocked_keyslot(header, &state, key)? {
        Some(slot) => slot,
        None => {
            if stored == target {
                bail!("the data disk key does not unlock epochs {target:?}");
            }
            // The keyslot holding the recorded epochs; a disk without a token
            // is epoch 0 in slot 0.
            let old_slot = state.token_keyslot.unwrap_or(0);
            if !state.keyslots.contains(&old_slot) {
                bail!("the recorded LUKS keyslot {old_slot} does not exist");
            }
            info!("re-keying the data disk from epochs {stored:?} to {target:?}");
            let old_key = old_key(stored.0, stored.1).await?;
            if !unlocks(header, old_slot, &old_key)? {
                bail!(
                    "the key of epochs {stored:?} does not unlock the recorded keyslot {old_slot}"
                );
            }
            // A migration interrupted before a later rotation leaves a second
            // keyslot whose epochs were never recorded, or are no longer the
            // recorded ones. Drop it, now that the recorded key is confirmed,
            // to make room for the current key.
            for &stale in state.keyslots.iter().filter(|&&slot| slot != old_slot) {
                kill_luks_slot(device, stale)?;
            }
            add_luks_key(device, header, &old_key, key, old_slot ^ 1)?;
            state = load_luks_header(device, header)?;
            unlocked_keyslot(header, &state, key)?
                .context("the added LUKS keyslot does not unlock with the data disk key")?
        }
    };
    let mut changed = false;
    let recorded = (
        state.token_keyslot,
        state.root_epoch.unwrap_or(0),
        state.app_epoch,
    );
    let legacy = target == (0, 0) && state.token_keyslot.is_none();
    if !legacy && recorded != (Some(slot), target.0, target.1) {
        write_luks_epochs(device, slot, target.0, target.1)?;
        changed = true;
    }
    for &stale in state.keyslots.iter().filter(|&&stale| stale != slot) {
        kill_luks_slot(device, stale)?;
        changed = true;
    }
    if changed {
        state = load_luks_header(device, header)?;
        let recorded = (state.token_keyslot, state.root_epoch, state.app_epoch);
        if state.keyslots != [slot] || recorded != (Some(slot), Some(target.0), target.1) {
            bail!("the updated LUKS header does not record epochs {target:?}");
        }
    }
    Ok(state)
}

/// Set by luksFormat and cleared once the filesystem exists, so a disk still
/// carrying it was interrupted mid-initialization and holds no data.
pub(super) const LUKS_INITIALIZING_LABEL: &str = "dstack-initializing";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LuksHeaderState {
    /// The header carries [`LUKS_INITIALIZING_LABEL`].
    pub(super) initializing: bool,
    /// Root epoch recorded in the dstack token; `None` means epoch 0.
    pub(super) root_epoch: Option<u32>,
    pub(super) app_epoch: u32,
    /// Keyslot the dstack token records the epochs of.
    pub(super) token_keyslot: Option<u8>,
    /// Sorted keyslot ids; a second one exists only mid-migration.
    pub(super) keyslots: Vec<u8>,
}

pub(super) fn validate_luks2_headers(mut reader: impl std::io::Read) -> Result<LuksHeaderState> {
    let primary = validate_single_luks2_header(&mut reader, 0)?;
    let secondary = validate_single_luks2_header(&mut reader, 1)?;
    if primary != secondary {
        bail!("LUKS header copies disagree");
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

    let mut keyslot_ids: Vec<u8> = keyslots.keys().copied().collect();
    keyslot_ids.sort_unstable();
    if keyslot_ids != [0] && keyslot_ids != [1] && keyslot_ids != [0, 1] {
        bail!("Invalid LUKS keyslots");
    }
    let (root_epoch, app_epoch, token_keyslot) = match tokens.len() {
        0 => (None, 0, None),
        1 => {
            let token = tokens.get(&0).context("Invalid LUKS token id")?;
            let slot = match &token.keyslots[..] {
                [slot] => slot.parse::<u8>().ok(),
                _ => None,
            };
            if token.kind != ROOT_EPOCH_TOKEN_TYPE
                || !slot.is_some_and(|s| keyslots.contains_key(&s))
            {
                bail!("Invalid LUKS token");
            }
            let root_epoch = token.root_epoch.context("LUKS token has no root epoch")?;
            (Some(root_epoch), token.app_epoch, slot)
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

    for keyslot in keyslots.values() {
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
        } = keyslot;
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
        let mut keyslots = keyslots.clone();
        keyslots.sort_unstable();
        if keyslots != keyslot_ids {
            bail!("Invalid LUKS digest keyslots: {keyslots:?}");
        }
        if segments != &[0] {
            bail!("Invalid LUKS digest segments: {segments:?}");
        }
    }
    Ok(LuksHeaderState {
        initializing,
        root_epoch,
        app_epoch,
        token_keyslot,
        keyslots: keyslot_ids,
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
            app_epoch: 0,
            token_keyslot: None,
            keyslots: vec![0],
        }
    );
    let hdr_size = LuksHeader::parse(&header_data).unwrap().hdr_size as usize;
    for copy in [0, hdr_size] {
        header_data[copy + 24..copy + 24 + LUKS_INITIALIZING_LABEL.len()]
            .copy_from_slice(LUKS_INITIALIZING_LABEL.as_bytes());
    }
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

#[cfg(test)]
struct TestDisk {
    dir: tempfile::TempDir,
    image: std::path::PathBuf,
    header: std::path::PathBuf,
}

#[cfg(test)]
impl TestDisk {
    /// A disk formatted with `key` and recording `epochs`, or `None` without
    /// cryptsetup.
    fn new(key: &str, epochs: Option<(u32, u32)>) -> Option<Self> {
        if Command::new("cryptsetup")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("cryptsetup is unavailable; skipping");
            return None;
        }
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("disk.img");
        let header = dir.path().join("header");
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
        assert_eq!(run_with_input(format, key.as_bytes()).unwrap(), Some(0));
        if let Some((root, app)) = epochs {
            write_luks_epochs(&image, 0, root, app).unwrap();
        }
        Some(Self { dir, image, header })
    }

    fn state(&self) -> LuksHeaderState {
        load_luks_header(&self.image, &self.header).unwrap()
    }

    fn unlocks(&self, key: &str) -> bool {
        let test = cryptsetup(&["open", "--test-passphrase", "-d-"], &self.image);
        run_with_input(test, key.as_bytes()).unwrap() == Some(0)
    }

    fn add_key(&self, old: &str, new: &str, slot: u8) {
        add_luks_key(&self.image, &self.header, old, new, slot).unwrap();
    }

    /// Sync to `target`; `old` is the only key the KMS would hand out.
    async fn sync(
        &self,
        key: &str,
        target: (u32, u32),
        old: Option<(u32, u32, &str)>,
    ) -> Result<LuksHeaderState> {
        let old_key = |root, app| {
            let key = old
                .filter(|(r, a, _)| (*r, *a) == (root, app))
                .map(|(_, _, key)| key.to_owned())
                .context("the KMS does not serve this epoch");
            std::future::ready(key)
        };
        sync_luks_epochs(
            &self.image,
            &self.header,
            self.state(),
            key,
            target,
            old_key,
        )
        .await
    }

    fn assert_synced(&self, key: &str, target: (u32, u32), slot: u8) {
        let state = self.state();
        assert_eq!(state.keyslots, [slot]);
        assert_eq!(state.token_keyslot, Some(slot));
        assert_eq!(
            (state.root_epoch, state.app_epoch),
            (Some(target.0), target.1)
        );
        assert!(self.unlocks(key));
        assert!(!self.dir.path().join("old-key").exists());
    }
}

#[tokio::test]
async fn test_luks_epoch_migration() {
    let Some(disk) = TestDisk::new("k1", Some((1, 0))) else {
        return;
    };
    disk.sync("k2", (2, 0), Some((1, 0, "k1"))).await.unwrap();
    disk.assert_synced("k2", (2, 0), 1);
    assert!(!disk.unlocks("k1"));
    disk.sync("k3", (2, 1), Some((2, 0, "k2"))).await.unwrap();
    disk.assert_synced("k3", (2, 1), 0);
    assert!(!disk.unlocks("k2"));
    // Already current: no key is requested.
    disk.sync("k3", (2, 1), None).await.unwrap();
    disk.assert_synced("k3", (2, 1), 0);
}

#[tokio::test]
async fn test_luks_epoch_migration_resumes_after_each_step() {
    // Crash after luksAddKey, then after the token import as well.
    for record in [false, true] {
        let Some(disk) = TestDisk::new("k1", Some((1, 0))) else {
            return;
        };
        disk.add_key("k1", "k2", 1);
        if record {
            write_luks_epochs(&disk.image, 1, 2, 0).unwrap();
        }
        disk.sync("k2", (2, 0), None).await.unwrap();
        disk.assert_synced("k2", (2, 0), 1);
        assert!(!disk.unlocks("k1"));
    }
}

#[tokio::test]
async fn test_luks_epoch_migration_resumes_after_a_later_rotation() {
    // Interrupted while migrating to epoch 1, then rotated to epoch 2 before
    // the next boot: the current key unlocks neither keyslot.
    for record in [false, true] {
        let Some(disk) = TestDisk::new("k0", None) else {
            return;
        };
        disk.add_key("k0", "k1", 1);
        let old = if record {
            write_luks_epochs(&disk.image, 1, 1, 0).unwrap();
            (1, 0, "k1")
        } else {
            (0, 0, "k0")
        };
        disk.sync("k2", (2, 0), Some(old)).await.unwrap();
        disk.assert_synced("k2", (2, 0), if record { 0 } else { 1 });
        assert!(!disk.unlocks("k0"));
        assert!(!disk.unlocks("k1"));
    }
}

#[tokio::test]
async fn test_luks_stale_keyslot_is_kept_until_the_recorded_key_is_confirmed() {
    let Some(disk) = TestDisk::new("k0", None) else {
        return;
    };
    disk.add_key("k0", "k1", 1);
    let interrupted = disk.state();
    // The KMS denies the recorded epoch, or hands out a key that does not
    // unlock its keyslot: both keyslots stay.
    assert!(disk.sync("k2", (2, 0), None).await.is_err());
    let err = disk
        .sync("k2", (2, 0), Some((0, 0, "k1")))
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("does not unlock the recorded keyslot 0"),
        "{err:#}"
    );
    assert_eq!(disk.state(), interrupted);
    assert!(disk.unlocks("k0") && disk.unlocks("k1"));
}

#[tokio::test]
async fn test_luks_epoch_migration_with_disagreeing_header_copies() {
    let Some(disk) = TestDisk::new("k1", Some((1, 0))) else {
        return;
    };
    disk.add_key("k1", "k2", 1);
    let before = fs::read(&disk.image).unwrap();
    write_luks_epochs(&disk.image, 1, 2, 0).unwrap();
    let after = fs::read(&disk.image).unwrap();
    let hdr_size = LuksHeader::parse(&before).unwrap().hdr_size as usize;
    // Interrupted between writing the two header copies, in either order.
    for (primary, secondary) in [(&after, &before), (&before, &after)] {
        let mut image = primary.clone();
        image[hdr_size..2 * hdr_size].copy_from_slice(&secondary[hdr_size..2 * hdr_size]);
        fs::write(&disk.image, image).unwrap();
        disk.sync("k2", (2, 0), None).await.unwrap();
        disk.assert_synced("k2", (2, 0), 1);
    }
}

#[tokio::test]
async fn test_luks_epoch_migration_failures_keep_the_old_epochs() {
    let Some(disk) = TestDisk::new("k1", Some((1, 0))) else {
        return;
    };
    let unchanged = disk.state();
    // The KMS denies the old epoch.
    assert!(disk.sync("k2", (2, 0), None).await.is_err());
    // luksAddKey fails: the KMS answers with a key that does not unlock.
    assert!(disk.sync("k2", (2, 0), Some((1, 0, "bad"))).await.is_err());
    // The disk records a root epoch newer than the current one.
    let err = disk.sync("k0", (0, 3), None).await.unwrap_err();
    assert!(err.to_string().contains("exceed"), "{err:#}");
    assert_eq!(disk.state(), unchanged);
    assert!(disk.unlocks("k1"));

    let app_ahead = TestDisk::new("k1", Some((1, 2))).unwrap();
    let err = app_ahead.sync("k1", (1, 1), None).await.unwrap_err();
    assert!(err.to_string().contains("exceed"), "{err:#}");

    // A failed token import is an error.
    let not_luks = disk.dir.path().join("not-luks");
    fs::write(&not_luks, [0; 4096]).unwrap();
    assert!(write_luks_epochs(&not_luks, 0, 2, 0).is_err());
}

#[tokio::test]
async fn test_luks_epoch_zero_disk_is_left_untouched() {
    let Some(disk) = TestDisk::new("k0", None) else {
        return;
    };
    let unchanged = disk.state();
    disk.sync("k0", (0, 0), None).await.unwrap();
    assert_eq!(disk.state(), unchanged);
    assert_eq!(unchanged.token_keyslot, None);
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
