// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! `dstack-mr` CLI.
//!
//! Exposes build-time OS-image measurement material/hash computations.

use anyhow::{bail, Context, Result};
use dstack_types::OsImageMeasurementDocument;
use serde_json::Value;
use std::path::Path;

const USAGE: &str = "\
usage:
  dstack-mr measure-os <image_dir>
  dstack-mr inspect-measurement <measurement_json>
  dstack-mr sev-os-image-hash <image_dir>
  dstack-mr tdx-os-image-measurement <image_dir>
  dstack-mr tdx-os-image-hash <image_dir>

features:
  cbor-measurement-v2";

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("measure-os") => {
            let image_dir = args.next().context(USAGE)?;
            let document = dstack_mr::measurement::os_image_measurement_document_for_image_dir(
                Path::new(&image_dir),
            )
            .context("failed to compute os image measurement document")?;
            println!(
                "{}",
                serde_json::to_string(&document)
                    .context("failed to serialize os image measurement document")?
            );
            Ok(())
        }
        Some("inspect-measurement") => {
            let measurement_json = args.next().context(USAGE)?;
            let document = inspect_measurement(Path::new(&measurement_json))
                .context("failed to inspect os image measurement document")?;
            println!(
                "{}",
                serde_json::to_string_pretty(&document)
                    .context("failed to serialize decoded measurement document")?
            );
            Ok(())
        }
        Some("sev-os-image-hash") => {
            let image_dir = args.next().context(USAGE)?;
            let hash = dstack_mr::sev::sev_os_image_hash_for_image_dir(Path::new(&image_dir))
                .context("failed to compute amd sev-snp os_image_hash")?;
            println!("{}", hex::encode(hash));
            Ok(())
        }
        Some("tdx-os-image-measurement") => {
            let image_dir = args.next().context(USAGE)?;
            let document = dstack_mr::tdx::tdx_os_image_measurement_document_for_image_dir(
                Path::new(&image_dir),
            )
            .context("failed to compute tdx os image measurement material")?;
            println!(
                "{}",
                serde_json::to_string(&document)
                    .context("failed to serialize tdx measurement material")?
            );
            Ok(())
        }
        Some("tdx-os-image-hash") => {
            let image_dir = args.next().context(USAGE)?;
            let hash = dstack_mr::tdx::tdx_os_image_hash_for_image_dir(Path::new(&image_dir))
                .context("failed to compute tdx os_image_hash")?;
            println!("{}", hex::encode(hash));
            Ok(())
        }
        Some("-h") | Some("--help") => {
            println!("{USAGE}");
            Ok(())
        }
        Some(other) => bail!("unknown subcommand {other:?}\n{USAGE}"),
        None => bail!("{USAGE}"),
    }
}

fn inspect_measurement(path: &Path) -> Result<Value> {
    let document_text = fs_err::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let document: OsImageMeasurementDocument = serde_json::from_str(&document_text)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    let mut out: Value = serde_json::from_str(&document_text)
        .with_context(|| format!("failed to parse {}", path.display()))?;

    if let (Some(tdx), Some(tdx_value)) = (&document.tdx, out.get_mut("tdx")) {
        replace_measurement_field(
            tdx_value,
            tdx.decode_measurement_value()
                .map_err(anyhow::Error::msg)
                .context("failed to decode tdx measurement CBOR")?,
        );
    }
    if let (Some(snp), Some(snp_value)) = (&document.snp, out.get_mut("snp")) {
        replace_measurement_field(
            snp_value,
            snp.decode_measurement_value()
                .map_err(anyhow::Error::msg)
                .context("failed to decode snp measurement CBOR")?,
        );
    }
    Ok(out)
}

fn replace_measurement_field(section: &mut Value, decoded_measurement: Value) {
    let Some(section) = section.as_object_mut() else {
        return;
    };
    if section.contains_key("measurement") {
        section.insert("measurement".to_string(), decoded_measurement);
    } else if section.contains_key("m") {
        section.insert("m".to_string(), decoded_measurement);
    }
}
