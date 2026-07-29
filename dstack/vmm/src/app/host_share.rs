// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Host-to-guest shared-file disk creation.

use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{Context, Result};
use dstack_types::shared_filenames::HOST_SHARED_DISK_LABEL;
use fatfs::{FileSystem, FormatVolumeOptions, FsOptions};
use fs_err as fs;
use tempfile::NamedTempFile;

/// Creates a FAT32 disk image containing the files in `shared_dir`.
pub(super) fn create_shared_disk(
    disk_path: impl AsRef<Path>,
    shared_dir: impl AsRef<Path>,
) -> Result<()> {
    let disk_path = disk_path.as_ref();
    let shared_dir = shared_dir.as_ref();
    let parent = disk_path.parent().unwrap_or_else(|| Path::new("."));
    let mut temporary = NamedTempFile::new_in(parent)
        .with_context(|| format!("failed to create temporary disk image in {}", parent.display()))?;

    // Must be large enough to hold all host-shared files (app-compose.json and
    // .user-config can each be up to 50 MiB, see HostShared::copy) plus FAT32 overhead.
    const DISK_SIZE: u64 = 128 * 1024 * 1024;

    // Back the image by a file (sparse until written) and stream files into it so
    // peak memory stays bounded regardless of DISK_SIZE or input file sizes.
    let image = temporary.as_file_mut();
    image
        .set_len(DISK_SIZE)
        .context("failed to size disk image")?;

    {
        let mut label_bytes = [b' '; 11];
        let label = HOST_SHARED_DISK_LABEL.as_bytes();
        let copy_len = label.len().min(label_bytes.len());
        label_bytes[..copy_len].copy_from_slice(&label[..copy_len]);
        let format_opts = FormatVolumeOptions::new()
            .fat_type(fatfs::FatType::Fat32)
            .volume_label(label_bytes);
        fatfs::format_volume(&mut image, format_opts).context("failed to format disk as FAT32")?;
    }

    image
        .seek(SeekFrom::Start(0))
        .context("failed to seek to start")?;
    let filesystem =
        FileSystem::new(&mut image, FsOptions::new()).context("failed to open FAT32 filesystem")?;
    let root_dir = filesystem.root_dir();

    for entry in fs::read_dir(shared_dir).context("failed to read shared directory")? {
        let entry = entry.context("failed to read directory entry")?;
        let path = entry.path();
        let file_type = entry.file_type().context("failed to inspect shared entry")?;
        if !file_type.is_file() {
            continue;
        }

        let filename = entry.file_name();
        let filename = filename.to_string_lossy();
        let mut source = fs::File::open(&path)
            .with_context(|| format!("failed to open file {}", path.display()))?;
        let mut destination = root_dir
            .create_file(&filename)
            .with_context(|| format!("failed to create file {filename} in FAT32"))?;
        std::io::copy(&mut source, &mut destination)
            .with_context(|| format!("failed to write file {filename} to FAT32"))?;
        destination.flush().context("failed to flush FAT32 file")?;
    }

    drop(root_dir);
    drop(filesystem);
    temporary
        .persist(disk_path)
        .map_err(|error| error.error)
        .with_context(|| format!("failed to publish disk image at {}", disk_path.display()))?;
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::create_shared_disk;
    use fatfs::{FileSystem, FsOptions};
    use std::{fs, io::Read, sync::Arc, thread};
    use tempfile::TempDir;

    fn read_file(disk: &std::path::Path, name: &str) -> Vec<u8> {
        let mut image = fs::OpenOptions::new().read(true).write(true).open(disk).unwrap();
        let filesystem = FileSystem::new(&mut image, FsOptions::new()).unwrap();
        let mut file = filesystem.root_dir().open_file(name).unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).unwrap();
        contents
    }

    #[test]
    fn creates_fixed_size_disk_with_exact_regular_file_contents() {
        let root = TempDir::new().unwrap();
        let shared = root.path().join("shared");
        fs::create_dir(&shared).unwrap();
        fs::write(shared.join("app-compose.json"), b"compose").unwrap();
        fs::create_dir(shared.join("ignored-directory")).unwrap();
        let disk = root.path().join("host-shared.img");
        create_shared_disk(&disk, &shared).unwrap();
        assert_eq!(fs::metadata(&disk).unwrap().len(), 128 * 1024 * 1024);
        assert_eq!(read_file(&disk, "app-compose.json"), b"compose");
    }

    #[test]
    fn missing_or_oversized_sources_never_publish_partial_disk() {
        let root = TempDir::new().unwrap();
        let missing_disk = root.path().join("missing.img");
        assert!(create_shared_disk(&missing_disk, root.path().join("absent")).is_err());
        assert!(!missing_disk.exists());

        let shared = root.path().join("oversized");
        fs::create_dir(&shared).unwrap();
        let source = fs::File::create(shared.join("too-large")).unwrap();
        source.set_len(129 * 1024 * 1024).unwrap();
        let oversized_disk = root.path().join("oversized.img");
        assert!(create_shared_disk(&oversized_disk, &shared).is_err());
        assert!(!oversized_disk.exists());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_sources_cannot_escape_shared_root() {
        use std::os::unix::fs::symlink;
        let root = TempDir::new().unwrap();
        let shared = root.path().join("shared");
        fs::create_dir(&shared).unwrap();
        fs::write(root.path().join("outside-secret"), b"must-not-copy").unwrap();
        fs::write(shared.join("regular"), b"regular").unwrap();
        symlink(root.path().join("outside-secret"), shared.join("escape")).unwrap();
        let disk = root.path().join("host-shared.img");
        create_shared_disk(&disk, &shared).unwrap();
        assert_eq!(read_file(&disk, "regular"), b"regular");
        let mut image = fs::OpenOptions::new().read(true).write(true).open(disk).unwrap();
        let filesystem = FileSystem::new(&mut image, FsOptions::new()).unwrap();
        assert!(filesystem.root_dir().open_file("escape").is_err());
    }

    #[test]
    fn concurrent_publication_never_exposes_partial_image() {
        let root = TempDir::new().unwrap();
        let shared = root.path().join("shared");
        fs::create_dir(&shared).unwrap();
        fs::write(shared.join("payload"), vec![7_u8; 1024 * 1024]).unwrap();
        let disk = Arc::new(root.path().join("host-shared.img"));
        let shared = Arc::new(shared);
        let workers: Vec<_> = (0..2)
            .map(|_| {
                let disk = Arc::clone(&disk);
                let shared = Arc::clone(&shared);
                thread::spawn(move || create_shared_disk(disk.as_path(), shared.as_path()))
            })
            .collect();
        for worker in workers {
            worker.join().unwrap().unwrap();
        }
        assert_eq!(read_file(&disk, "payload"), vec![7_u8; 1024 * 1024]);
    }
}
