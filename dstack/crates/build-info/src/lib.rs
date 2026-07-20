// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Common compile-time build information for dstack binaries.

#[doc(hidden)]
pub use git_version::git_version as __git_version;

/// Returns the current Git commit as `git:<hash>`.
///
/// Tags are deliberately excluded because dstack is a monorepo containing
/// component-specific tags. Letting `git describe` select the nearest tag can
/// therefore report an unrelated component's version.
#[macro_export]
macro_rules! git_revision {
    () => {
        $crate::__git_version!(
            args = [
                "--abbrev=20",
                "--always",
                "--dirty=-modified",
                "--exclude=*"
            ],
            prefix = "git:",
            fallback = "unknown"
        )
    };
}

/// Returns the calling package's version and Git revision for display.
///
/// The result has the form `v0.6.0 (git:0123456789abcdef0123)`. This is a
/// macro so `CARGO_PKG_VERSION` is evaluated for the calling package rather
/// than for `dstack-build-info` itself.
#[macro_export]
macro_rules! app_version {
    () => {
        format!(
            "v{} ({})",
            env!("CARGO_PKG_VERSION"),
            $crate::git_revision!()
        )
    };
}
