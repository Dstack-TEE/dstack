// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Build a docker overlay2 image store, laid out deterministically.
//!
//! The `oci` module pulls an image's layers; this module lays them out into the
//! on-disk overlay2 store that docker reads.
//!
//! docker's own store is non-deterministic in two ways: it gives each layer a
//! random cache-id, and it stamps wall-clock times. Here the cache-id is the
//! layer's chain-id instead, so the store bytes are a pure function of the
//! pinned layer digests.
//!
//! Whiteouts in the layer tars (the AUFS `.wh.` markers) become the form
//! overlay2 wants on disk: a `0:0` char device, or the `trusted.overlay.opaque`
//! xattr. Both need root.

use std::collections::BTreeMap;
use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use flate2::read::GzDecoder;
use fs_err as fs;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::oci::{PulledImage, PulledLayer};

/// Build the overlay2 store for `images` under `root`.
///
/// Returns each image's top chain-id, in the same order as `images`. That
/// chain-id is what the verity volume ultimately vouches for.
pub fn build_store(images: &[PulledImage], root: &Path) -> Result<Vec<String>> {
    fs::create_dir_all(root.join("overlay2/l"))?;
    fs::create_dir_all(root.join("image/overlay2/layerdb/sha256"))?;
    fs::create_dir_all(root.join("image/overlay2/imagedb/content/sha256"))?;

    let mut built: HashSet<String> = HashSet::new();
    // repo_name -> { "repo:tag" -> "sha256:imageid", "repo@digest" -> id }
    let mut repositories: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut tops = Vec::with_capacity(images.len());

    for img in images {
        let mut parent: Option<String> = None;
        let mut parent_short: Option<String> = None;
        let mut chain = String::new();
        for (i, diff_id) in img.diff_ids.iter().enumerate() {
            let diff_hex = strip_sha256(diff_id)?;
            chain = match &parent {
                None => diff_hex.to_string(),
                Some(p) => chain_id(p, diff_hex),
            };
            let short = short_link(&chain);

            // A layer shared by two images has the same chain-id; write it once.
            if built.insert(chain.clone()) {
                write_layer(
                    root,
                    &img.layers[i],
                    &img.reference,
                    i,
                    diff_id,
                    &chain,
                    &short,
                    parent.as_deref(),
                    parent_short.as_deref(),
                )?;
            }
            parent = Some(chain.clone());
            parent_short = Some(short);
        }

        // imagedb: the config blob verbatim, keyed by its digest (the image id).
        let image_id = strip_sha256(&img.config_digest)?;
        write_bytes(
            root.join("image/overlay2/imagedb/content/sha256")
                .join(image_id),
            &img.config_bytes,
        )?;
        // repositories.json: map the exact canonical reference the user pinned
        // (`repo:tag` or `repo@sha256:...`) to the image id, plus the resolved
        // manifest digest as a secondary alias.
        let entry = repositories.entry(img.repo_name.clone()).or_default();
        entry.insert(img.ref_key.clone(), img.config_digest.clone());
        entry.insert(
            format!("{}@{}", img.repo_name, img.manifest_digest),
            img.config_digest.clone(),
        );
        tops.push(chain);
    }

    write_bytes(
        root.join("image/overlay2/repositories.json"),
        serde_json::to_vec(&json!({ "Repositories": repositories }))?.as_slice(),
    )?;
    Ok(tops)
}

/// Write one layer into the store, under its `chain` id.
///
/// Extracts the layer's files, checks them against `diff_id`, then records the
/// overlay2 link and the layerdb entry. `parent` and `parent_short` describe the
/// layer directly below; both are `None` for the base layer.
#[allow(clippy::too_many_arguments)]
fn write_layer(
    root: &Path,
    layer: &PulledLayer,
    reference: &str,
    layer_index: usize,
    diff_id: &str,
    chain: &str,
    short: &str,
    parent: Option<&str>,
    parent_short: Option<&str>,
) -> Result<()> {
    let layer_dir = root.join("overlay2").join(chain);
    let diff_dir = layer_dir.join("diff");
    fs::create_dir_all(&diff_dir)?;

    let (layer_size, actual_diff) = extract_layer(&layer.data, &layer.media_type, &diff_dir)
        .with_context(|| format!("extracting layer {layer_index} of {reference}"))?;

    // The extracted files must hash to the diff_id the config claims. Otherwise a
    // registry could hand us content that doesn't match its (pinned) config, and
    // we'd bake it in anyway.
    if actual_diff != diff_id {
        bail!(
            "layer {layer_index} of {reference} does not match its diff_id \
             (got {actual_diff}, config says {diff_id})"
        );
    }

    // overlay2 finds a layer through the `l/<short>` symlink and its `link` file.
    symlink(
        format!("../{chain}/diff"),
        root.join("overlay2/l").join(short),
    )?;
    write(layer_dir.join("link"), short)?;
    if let Some(ps) = parent_short {
        write(layer_dir.join("lower"), &lower_chain(root, ps)?)?;
    }

    let layerdb = root.join("image/overlay2/layerdb/sha256").join(chain);
    fs::create_dir_all(&layerdb)?;
    write(layerdb.join("diff"), diff_id)?;
    write(layerdb.join("cache-id"), chain)?;
    write(layerdb.join("size"), &layer_size.to_string())?;
    if let Some(p) = parent {
        write(layerdb.join("parent"), &format!("sha256:{p}"))?;
    }
    Ok(())
}

/// docker's chain-id for a layer: `sha256("sha256:<parent> sha256:<diff>")`.
fn chain_id(parent_chain_hex: &str, diff_hex: &str) -> String {
    let mut h = Sha256::new();
    h.update(format!("sha256:{parent_chain_hex} sha256:{diff_hex}").as_bytes());
    hex::encode(h.finalize())
}

/// Deterministic 26-char [A-Z0-9] overlay2 link name (docker uses a random one).
fn short_link(chain_hex: &str) -> String {
    let mut s = String::from("L");
    s.push_str(&chain_hex[..25].to_uppercase());
    s
}

/// Build the `lower` file for a layer, given its parent's link name.
///
/// overlay2 lists every ancestor there, nearest first. We build that by taking
/// the parent's own `lower` and prepending the parent.
fn lower_chain(root: &Path, parent_short: &str) -> Result<String> {
    // resolve the parent's chain dir from its l/ symlink to read its `lower`.
    let parent_dir = fs::read_link(root.join("overlay2/l").join(parent_short))?;
    // ../<chain>/diff -> <chain>
    let chain = parent_dir
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        .context("bad parent link")?
        .to_string();
    let plower = root.join("overlay2").join(&chain).join("lower");
    let mut parts = vec![format!("l/{parent_short}")];
    if let Ok(existing) = fs::read_to_string(&plower) {
        parts.extend(existing.split(':').map(str::to_string));
    }
    Ok(parts.join(":"))
}

/// Extract a layer tar into `dest`, converting AUFS whiteouts as it goes.
///
/// Handles gzip and plain tar. Returns two things: the layer's uncompressed size
/// (what docker records), and its diff-id — the sha256 of the whole decompressed
/// tar, which the caller checks against the config.
fn extract_layer(data: &[u8], media_type: &str, dest: &Path) -> Result<(u64, String)> {
    let is_gzip =
        media_type.contains("gzip") || (data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b);
    let decompressed: Box<dyn Read> = if is_gzip {
        Box::new(GzDecoder::new(data))
    } else {
        Box::new(data)
    };
    let mut ar = tar::Archive::new(HashingReader::new(decompressed));
    ar.set_preserve_permissions(true);
    ar.set_preserve_mtime(true);
    ar.set_unpack_xattrs(true);
    ar.set_preserve_ownerships(true);

    let mut total = 0u64;
    for entry in ar.entries()? {
        let mut entry = entry?;
        if entry.header().entry_type().is_file() {
            total += entry.header().size().unwrap_or(0);
        }
        let path = entry.path()?.into_owned();
        let name = match path.file_name().and_then(|s| s.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };

        if let Some(rest) = name.strip_prefix(".wh.") {
            // Whiteouts are placed by hand (mknod / an xattr) rather than through
            // the tar crate, so they need their own containment. Without it a
            // hostile layer could escape `dest` — lexically, or through a
            // symlinked parent it planted earlier — and we run as root.
            // `safe_subpath` won't follow a symlink out of `dest`.
            let out_parent =
                match safe_subpath(dest, path.parent().unwrap_or_else(|| Path::new(""))) {
                    Some(p) => p,
                    None => continue,
                };
            if name == ".wh..wh..opq" {
                fs::create_dir_all(&out_parent)?;
                xattr::set(&out_parent, "trusted.overlay.opaque", b"y")
                    .context("setting overlay opaque xattr (need root)")?;
            } else if rest.starts_with(".wh.") {
                // other reserved aufs metadata (e.g. `.wh..wh..plnk`) — not a
                // whiteout for `rest`; ignore.
            } else if rest.is_empty() || rest == "." || rest == ".." {
                // a name like `.wh.`, `.wh..`, or `.wh...` would target the parent
                // dir itself or escape it; ignore.
            } else {
                fs::create_dir_all(&out_parent)?;
                let target = out_parent.join(rest);
                let _ = remove_any(&target);
                mknod_whiteout(&target).context("creating overlay whiteout (need root)")?;
            }
            continue;
        }
        // normal entry — the tar crate sandboxes this against `dest` (rejects
        // `..`/absolute and creates parents itself).
        entry.unpack_in(dest)?;
    }
    // drain any trailing padding the entry iterator didn't read, so the digest
    // covers the whole tar, then finalize the diff-id.
    let mut hr = ar.into_inner();
    std::io::copy(&mut hr, &mut std::io::sink())?;
    let diff_id = format!("sha256:{}", hex::encode(hr.finalize()));
    Ok((total, diff_id))
}

/// A reader that sha256's every byte passing through it.
///
/// This lets us compute a layer's diff-id while extracting it, instead of
/// decompressing the layer a second time.
struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
}
impl<R: Read> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
        }
    }
    fn finalize(self) -> impl AsRef<[u8]> {
        self.hasher.finalize()
    }
}
impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}

/// Resolve `rel` under `dest`, but only if it stays inside `dest`.
///
/// Returns `None` for a `..` or absolute component. It also refuses to walk
/// through any component that already exists as a symlink, so a symlink a
/// hostile layer planted earlier can't be used to escape. (The tar crate gets
/// the same guarantee by canonicalizing.)
fn safe_subpath(dest: &Path, rel: &Path) -> Option<PathBuf> {
    use std::path::Component;
    let mut cur = dest.to_path_buf();
    for comp in rel.components() {
        match comp {
            Component::CurDir => {}
            Component::Normal(c) => {
                cur.push(c);
                if let Ok(md) = fs::symlink_metadata(&cur) {
                    if md.file_type().is_symlink() {
                        return None;
                    }
                }
            }
            // absolute root, `..`, or a Windows prefix: reject outright.
            _ => return None,
        }
    }
    Some(cur)
}

/// overlay2 whiteout: a character device with major/minor 0/0.
fn mknod_whiteout(path: &Path) -> Result<()> {
    use rustix::fs::{mknodat, FileType, Mode, CWD};
    mknodat(CWD, path, FileType::CharacterDevice, Mode::empty(), 0)?;
    Ok(())
}

fn remove_any(path: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(e) => Err(e),
    }
}

fn strip_sha256(d: &str) -> Result<&str> {
    let hex = d
        .strip_prefix("sha256:")
        .with_context(|| format!("expected sha256: digest, got '{d}'"))?;
    // validate here so every downstream chain-id / link name is 64 hex chars,
    // and slicing (e.g. short_link's [..25]) can't panic on hostile registry data.
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("malformed sha256 digest '{d}' (expected 64 hex chars)");
    }
    Ok(hex)
}

fn symlink(target: impl AsRef<Path>, link: impl AsRef<Path>) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

fn write(path: PathBuf, contents: &str) -> std::io::Result<()> {
    fs::write(path, contents.as_bytes())
}

fn write_bytes(path: PathBuf, contents: &[u8]) -> std::io::Result<()> {
    fs::write(path, contents)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_sha256_validates_64_hex() {
        let ok = "a".repeat(64);
        assert_eq!(strip_sha256(&format!("sha256:{ok}")).unwrap(), ok);
        assert!(strip_sha256("nothex").is_err()); // no sha256: prefix
        assert!(strip_sha256("sha256:abc").is_err()); // too short (would panic short_link)
        assert!(strip_sha256(&format!("sha256:{}", "g".repeat(64))).is_err()); // not hex
        assert!(strip_sha256("sha256:€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€€").is_err());
        // multibyte
    }

    #[test]
    fn chain_id_matches_docker_formula() {
        // base layer chain-id == diff-id.
        let d = "0000000000000000000000000000000000000000000000000000000000000000";
        // second layer: sha256("sha256:<d> sha256:<d>")
        let c = chain_id(d, d);
        let mut h = Sha256::new();
        h.update(format!("sha256:{d} sha256:{d}").as_bytes());
        assert_eq!(c, hex::encode(h.finalize()));
    }

    #[test]
    fn short_link_is_26_upper_alnum() {
        let s = short_link("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
        assert_eq!(s.len(), 26);
        assert!(s.starts_with('L'));
        assert!(s
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
    }

    #[test]
    fn safe_subpath_rejects_traversal_absolute_and_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path();
        // plain nested paths resolve inside dest.
        assert_eq!(safe_subpath(dest, Path::new("a/b")), Some(dest.join("a/b")));
        assert_eq!(
            safe_subpath(dest, Path::new("./app")),
            Some(dest.join("app"))
        );
        // lexical escapes are refused.
        assert!(safe_subpath(dest, Path::new("../etc")).is_none());
        assert!(safe_subpath(dest, Path::new("/etc")).is_none());
        assert!(safe_subpath(dest, Path::new("a/../../etc")).is_none());
        // a planted symlink parent must not be traversed (the real exploit).
        std::os::unix::fs::symlink("/var", dest.join("evil")).unwrap();
        assert!(safe_subpath(dest, Path::new("evil")).is_none());
        assert!(safe_subpath(dest, Path::new("evil/lib")).is_none());
    }

    #[test]
    fn whiteout_through_symlinked_parent_cannot_escape() {
        // End-to-end: a hostile layer plants `evil -> <victim dir>` then a
        // whiteout `evil/.wh.keep`; without containment that would delete the
        // victim file outside dest, as root.
        use std::os::unix::fs::MetadataExt;
        let dest = tempfile::tempdir().unwrap();
        let victim = tempfile::tempdir().unwrap();
        fs::write(victim.path().join("keep"), b"x").unwrap();
        // stamp the tar entries with our own uid/gid so unpacking the symlink
        // doesn't need root to chown.
        let md = fs::metadata(victim.path()).unwrap();
        let (uid, gid) = (md.uid() as u64, md.gid() as u64);

        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        h.set_uid(uid);
        h.set_gid(gid);
        h.set_mode(0o777);
        b.append_link(&mut h, "evil", victim.path()).unwrap();
        let mut h2 = tar::Header::new_gnu();
        h2.set_entry_type(tar::EntryType::Regular);
        h2.set_size(0);
        h2.set_uid(uid);
        h2.set_gid(gid);
        h2.set_mode(0o644);
        b.append_data(&mut h2, "evil/.wh.keep", std::io::empty())
            .unwrap();
        let tar_bytes = b.into_inner().unwrap();

        extract_layer(
            &tar_bytes,
            "application/vnd.oci.image.layer.v1.tar",
            dest.path(),
        )
        .unwrap();

        assert!(
            victim.path().join("keep").exists(),
            "whiteout escaped dest through a symlinked parent"
        );
    }
}
