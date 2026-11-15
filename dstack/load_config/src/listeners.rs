// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Services that serve several Rocket listeners, each configured in
//! `[listeners.<name>]` on top of the shared `[listeners.default]`.

use std::collections::BTreeSet;

use anyhow::{bail, Result};
use figment::{providers::Serialized, value::Dict, Figment, Provider, Source};

/// The Rocket config of listener `name`: `[listeners.default]` without the
/// `uninherited` keys, overridden by `[listeners.<name>]`.
pub fn listener_figment(figment: &Figment, name: &str, uninherited: &[&str]) -> Result<Figment> {
    let mut defaults = figment
        .find_value("listeners.default")
        .ok()
        .and_then(|value| value.into_dict())
        .unwrap_or_default();
    defaults.retain(|key, _| !uninherited.contains(&key.as_str()));
    let listener = figment.find_value(&format!("listeners.{name}"))?;
    Ok(Figment::from(rocket::Config::default())
        .merge(Serialized::defaults(defaults))
        .merge(Serialized::defaults(listener)))
}

/// Refuse a config that sets a setting at its old location: each `(old, new)`
/// in `moved`, and any other top-level key besides `core` and `listeners`,
/// which the old listeners read as Rocket settings. The defaults use only the
/// new locations, so a key present was set by the operator. Rocket's own
/// defaults are always present at the top level, so those keys count only when
/// a config file sets them.
pub fn reject_moved_settings(figment: &Figment, moved: &[(&str, &str)]) -> Result<()> {
    let rocket_keys = keys(&Figment::from(rocket::Config::default()))?;
    let is_set = |key: &str| {
        figment.find_value(key).is_ok()
            && (!rocket_keys.contains(key)
                || figment
                    .find_metadata(key)
                    .is_some_and(|meta| matches!(meta.source, Some(Source::File(_)))))
    };
    let mut found: Vec<String> = moved
        .iter()
        .filter(|(old, _)| is_set(old))
        .map(|(old, new)| format!("{old} -> {new}"))
        .collect();
    found.extend(
        keys(figment)?
            .into_iter()
            .filter(|key| !["core", "listeners"].contains(&key.as_str()))
            .filter(|key| !moved.iter().any(|(old, _)| old == key))
            .filter(|key| is_set(key))
            .map(|key| format!("{key} -> listeners.default.{key}")),
    );
    if !found.is_empty() {
        bail!(
            "the config sets listener settings at their old locations; move them: {}",
            found.join(", ")
        );
    }
    Ok(())
}

/// The top-level keys of every profile.
fn keys(provider: &impl Provider) -> Result<BTreeSet<String>> {
    Ok(provider
        .data()?
        .into_values()
        .flat_map(Dict::into_keys)
        .collect())
}
