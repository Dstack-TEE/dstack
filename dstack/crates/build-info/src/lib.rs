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
///
/// Guest OS backends build the workspace without a `.git` directory in the
/// sandbox, so `DSTACK_BUILD_GIT_REVISION` overrides the value at compile time.
/// It must carry the full display string including the `git:` prefix, because
/// callers such as the guest agent's `Info.rev` field surface it verbatim.
/// The name is deliberately distinct from the Yocto backend's
/// `DSTACK_GIT_REVISION`, which carries a bare SHA for release metadata and
/// would otherwise be picked up here with the wrong format.
#[macro_export]
macro_rules! git_revision {
    () => {
        match option_env!("DSTACK_BUILD_GIT_REVISION") {
            Some(revision) => revision,
            None => $crate::__git_version!(
                args = [
                    "--abbrev=20",
                    "--always",
                    "--dirty=-modified",
                    "--exclude=*"
                ],
                prefix = "git:",
                fallback = "unknown"
            ),
        }
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

#[cfg(test)]
mod tests {
    #[test]
    fn git_revision_is_never_empty() {
        assert!(!crate::git_revision!().is_empty());
    }

    #[test]
    fn app_version_embeds_package_version_and_revision() {
        let version = crate::app_version!();
        assert!(version.starts_with(&format!("v{}", env!("CARGO_PKG_VERSION"))));
        assert!(version.ends_with(&format!("({})", crate::git_revision!())));
    }

    #[test]
    fn build_override_replaces_the_git_derived_revision() {
        // The override is read at compile time, so this asserts the contract
        // that applies to whichever of the two arms was expanded.
        match option_env!("DSTACK_BUILD_GIT_REVISION") {
            Some(revision) => assert_eq!(crate::git_revision!(), revision),
            None => assert!(crate::git_revision!().starts_with("git:")),
        }
    }
}
