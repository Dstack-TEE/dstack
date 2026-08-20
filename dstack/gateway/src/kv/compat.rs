// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Keeps a rolling upgrade from erasing fields the writer has never heard of.
//!
//! KV values are msgpack maps keyed by field name, so a gateway running an older
//! build already *reads* a newer record without tripping over the fields it does
//! not know. The write path is where the data is lost: `encode` serializes the
//! struct as this binary declares it, so the moment an older node rewrites a
//! record — a re-registration, an admin call, a lazily-filled port policy — the
//! newer fields are gone for the whole cluster, and the node that wrote them has
//! no way to tell.
//!
//! That makes "values may gain fields freely" true only while every node is on
//! the same build, which is exactly when it does not matter. This module makes it
//! true during the upgrade window: before a record is written, the fields present
//! in the stored copy that this binary does not declare are appended to the
//! outgoing encoding verbatim.
//!
//! # What counts as unknown
//!
//! Unknown is decided against the field list `T` *declares*, obtained from the
//! derived `Deserialize` impl, not against the keys the new encoding happens to
//! contain. The difference matters: a `#[serde(skip_serializing_if)]` field that
//! this binary deliberately cleared is absent from the encoding but present in
//! the declaration, so it stays cleared instead of being resurrected from the
//! stored copy. Aliases count as declared, so `#[serde(alias)]` is safe here too.
//!
//! # Records, not snapshots
//!
//! Only long-lived records carry fields forward — see [`is_long_lived_record`].
//! A snapshot key (a certificate, an attestation, a lock) is a complete new fact
//! on every write, and carrying a field across those writes would attribute the
//! previous snapshot's value to the new one. An older gateway renewing a
//! certificate would then publish, say, a stale chain alongside the key it just
//! issued: worse than the field being absent, because absent is a case the newer
//! reader already has to handle.
//!
//! # Top-level only
//!
//! Only the root map is merged. Below it, nothing distinguishes a struct encoded
//! as a map from a `BTreeMap` field: recursing would resurrect map entries that
//! were deliberately removed. So a value type gains new fields **at its root**;
//! a nested type that has to grow needs its own preservation (a
//! `#[serde(flatten)]` catch-all), and this module declines the merge for such a
//! type rather than half-doing it.
//!
//! A field this binary stops declaring is carried forever, since it is
//! indistinguishable from a field a newer peer wrote. Retiring one for real
//! needs an explicit list of names to drop on write; until something needs to be
//! retired, that list would have no entries to hold.

use rmp::Marker;
use serde::de::{self, Deserializer, Visitor};
use std::fmt;
use tracing::debug;

use super::keys;

/// Whether writes to `key` preserve fields this binary does not declare.
///
/// True for records with an identity that outlives any single write — an
/// instance, a node, a DNS credential, a domain or the certbot config — where a
/// write updates a record that already existed. False for snapshots, counters
/// and locks, where each write replaces the whole fact and a carried-over field
/// would describe the write before it.
pub fn is_long_lived_record(key: &str) -> bool {
    key.starts_with(keys::INST_PREFIX)
        || key.starts_with(keys::NODE_INFO_PREFIX)
        || key.starts_with(keys::DNS_CRED_PREFIX)
        || key == keys::GLOBAL_CERTBOT_CONFIG
        || (key.starts_with(keys::CERT_PREFIX) && key.ends_with("/config"))
}

/// Append the fields of `stored` that `T` does not declare to `encoded`.
///
/// Returns `encoded` untouched — today's behavior — whenever the merge cannot be
/// made safely: `T` is not a plain struct, either side is not a string-keyed
/// map, either side does not parse cleanly, or the merged bytes do not read
/// back as `T`. Preserving unknown fields is an improvement on the write path,
/// never a precondition for the write.
pub fn carry_unknown_fields<T: serde::de::DeserializeOwned>(
    key: &str,
    stored: &[u8],
    encoded: Vec<u8>,
) -> Vec<u8> {
    let Some(declared) = declared_fields::<T>() else {
        return encoded;
    };
    let Some((_, stored_fields)) = split_map(stored) else {
        return encoded;
    };
    let Some((header_len, encoded_fields)) = split_map(&encoded) else {
        return encoded;
    };

    let carried: Vec<&Field> = stored_fields
        .iter()
        .filter(|field| {
            !declared.contains(&field.name)
                && !encoded_fields.iter().any(|out| out.name == field.name)
        })
        .collect();
    if carried.is_empty() {
        return encoded;
    }

    let extra: usize = carried.iter().map(|field| field.raw.len()).sum();
    let mut out = Vec::with_capacity(encoded.len() + extra + MAX_MAP_HEADER_LEN);
    if write_map_header(&mut out, encoded_fields.len() + carried.len()).is_none() {
        return encoded;
    }
    out.extend_from_slice(&encoded[header_len..]);
    for field in &carried {
        out.extend_from_slice(field.raw);
    }

    // Never write a record this binary cannot read back. The field list says
    // which names `T` knows, not what it tolerates next to them: a
    // `deny_unknown_fields` type, or a stored record that repeats a key, would
    // otherwise turn a healthy write into a record its own writer can no longer
    // decode. Dropping a newer peer's field is the lesser failure — it is the
    // one this module exists to reduce, not one it may introduce.
    if let Err(err) = super::decode::<T>(&out) {
        debug!("declining to carry unknown fields for key {key}: {err:#}");
        return encoded;
    }

    debug!(
        "carried {} unknown field(s) forward for key {key}: {:?}",
        carried.len(),
        carried.iter().map(|field| field.name).collect::<Vec<_>>(),
    );
    out
}

/// The field names `T` declares, or `None` if `T` does not deserialize from a
/// plain struct.
///
/// `None` is the answer for every shape the merge must stay away from: a scalar,
/// an internally tagged enum (whose variants have disjoint fields, so merging
/// across a variant change would mix them), and a type using
/// `#[serde(flatten)]`, which reads as a map and already preserves what it does
/// not know.
fn declared_fields<T: serde::de::DeserializeOwned>() -> Option<&'static [&'static str]> {
    let mut fields = None;
    let _ = T::deserialize(FieldProbe { out: &mut fields });
    fields
}

/// A deserializer that answers nothing.
///
/// Its only purpose is the field list the derived `Deserialize` impl passes to
/// `deserialize_struct`; every other entry point refuses, which ends the
/// deserialization immediately.
struct FieldProbe<'a> {
    out: &'a mut Option<&'static [&'static str]>,
}

#[derive(Debug)]
struct ProbeDone;

impl fmt::Display for ProbeDone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("field probe")
    }
}

impl std::error::Error for ProbeDone {}

impl de::Error for ProbeDone {
    fn custom<T: fmt::Display>(_msg: T) -> Self {
        // Deliberately drops the message: the probe always fails, and formatting
        // a string for an error nobody reads would allocate on every write.
        ProbeDone
    }
}

impl<'de> Deserializer<'de> for FieldProbe<'_> {
    type Error = ProbeDone;

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        fields: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value, Self::Error> {
        *self.out = Some(fields);
        Err(ProbeDone)
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_any<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
        Err(ProbeDone)
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string bytes byte_buf
        option unit unit_struct seq tuple tuple_struct map enum identifier ignored_any
    }
}

/// A `map32` header is the longest msgpack map header.
const MAX_MAP_HEADER_LEN: usize = 5;

/// One top-level `key -> value` pair, borrowed from the buffer it was parsed
/// from so that carrying it forward copies the original bytes rather than
/// re-encoding a decoded value.
struct Field<'a> {
    name: &'a str,
    /// Key and value bytes, contiguous and verbatim.
    raw: &'a [u8],
}

/// Split a msgpack map into its header length and its top-level fields.
///
/// Returns `None` unless the buffer is exactly one map whose keys are all
/// strings. A scalar, an array (the positional struct encoding older releases
/// wrote), an enum encoded as a string, or trailing bytes all decline rather
/// than get reinterpreted.
fn split_map(buf: &[u8]) -> Option<(usize, Vec<Field<'_>>)> {
    let (header_len, count) = match Marker::from_u8(*buf.first()?) {
        Marker::FixMap(n) => (1, n as usize),
        Marker::Map16 => (3, read_uint(buf, 1, 2)?),
        Marker::Map32 => (5, read_uint(buf, 1, 4)?),
        _ => return None,
    };
    let mut pos = header_len;
    let mut fields = Vec::with_capacity(count.min(32));
    for _ in 0..count {
        let key_start = pos;
        let key_end = skip_value(buf, pos)?;
        let name = read_str(buf, key_start, key_end)?;
        pos = skip_value(buf, key_end)?;
        fields.push(Field {
            name,
            raw: buf.get(key_start..pos)?,
        });
    }
    // Trailing bytes mean this is not the value we think it is.
    (pos == buf.len()).then_some((header_len, fields))
}

/// The offset just past the msgpack value starting at `pos`, or `None` if the
/// input is malformed, truncated, or claims more elements than it has bytes for.
///
/// Iterative rather than recursive: the stored bytes come off the wire, and a
/// deeply nested value must not be able to exhaust the stack. `pending` stays
/// bounded by the remaining byte count because every element costs at least the
/// one byte of its own marker.
fn skip_value(buf: &[u8], mut pos: usize) -> Option<usize> {
    let mut pending: usize = 1;
    while pending > 0 {
        pending -= 1;
        let marker = Marker::from_u8(*buf.get(pos)?);
        pos = pos.checked_add(1)?;
        let (payload, children) = match marker {
            Marker::FixPos(_) | Marker::FixNeg(_) | Marker::Null | Marker::True | Marker::False => {
                (0, 0)
            }
            Marker::U8 | Marker::I8 => (1, 0),
            Marker::U16 | Marker::I16 => (2, 0),
            Marker::U32 | Marker::I32 | Marker::F32 => (4, 0),
            Marker::U64 | Marker::I64 | Marker::F64 => (8, 0),
            Marker::FixStr(len) => (len as usize, 0),
            Marker::Str8 | Marker::Bin8 => (1 + read_uint(buf, pos, 1)?, 0),
            Marker::Str16 | Marker::Bin16 => (2 + read_uint(buf, pos, 2)?, 0),
            Marker::Str32 | Marker::Bin32 => (4 + read_uint(buf, pos, 4)?, 0),
            // One type byte, then the payload.
            Marker::FixExt1 => (1 + 1, 0),
            Marker::FixExt2 => (1 + 2, 0),
            Marker::FixExt4 => (1 + 4, 0),
            Marker::FixExt8 => (1 + 8, 0),
            Marker::FixExt16 => (1 + 16, 0),
            Marker::Ext8 => (1 + 1 + read_uint(buf, pos, 1)?, 0),
            Marker::Ext16 => (2 + 1 + read_uint(buf, pos, 2)?, 0),
            Marker::Ext32 => (4 + 1 + read_uint(buf, pos, 4)?, 0),
            Marker::FixArray(len) => (0, len as usize),
            Marker::Array16 => (2, read_uint(buf, pos, 2)?),
            Marker::Array32 => (4, read_uint(buf, pos, 4)?),
            Marker::FixMap(len) => (0, (len as usize).checked_mul(2)?),
            Marker::Map16 => (2, read_uint(buf, pos, 2)?.checked_mul(2)?),
            Marker::Map32 => (4, read_uint(buf, pos, 4)?.checked_mul(2)?),
            // Never used by the spec, and rejected by rmp-serde on read.
            Marker::Reserved => return None,
        };
        pos = pos.checked_add(payload)?;
        if pos > buf.len() {
            return None;
        }
        pending = pending.checked_add(children)?;
        if pending > buf.len() - pos {
            return None;
        }
    }
    Some(pos)
}

/// A big-endian unsigned integer of `size` bytes at `pos`.
fn read_uint(buf: &[u8], pos: usize, size: usize) -> Option<usize> {
    let bytes = buf.get(pos..pos.checked_add(size)?)?;
    bytes.iter().try_fold(0usize, |acc, byte| {
        acc.checked_mul(256)?.checked_add(*byte as usize)
    })
}

/// The contents of the msgpack string spanning `start..end`.
fn read_str(buf: &[u8], start: usize, end: usize) -> Option<&str> {
    let body = match Marker::from_u8(*buf.get(start)?) {
        Marker::FixStr(_) => start + 1,
        Marker::Str8 => start + 2,
        Marker::Str16 => start + 3,
        Marker::Str32 => start + 5,
        _ => return None,
    };
    std::str::from_utf8(buf.get(body..end)?).ok()
}

fn write_map_header(out: &mut Vec<u8>, count: usize) -> Option<()> {
    match count {
        0..=15 => out.push(0x80 | count as u8),
        16..=0xffff => {
            out.push(0xde);
            out.extend_from_slice(&(count as u16).to_be_bytes());
        }
        _ => {
            out.push(0xdf);
            out.extend_from_slice(&u32::try_from(count).ok()?.to_be_bytes());
        }
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;

    /// A record as an older build declares it.
    #[derive(Debug, Default, Serialize, Deserialize)]
    struct Old {
        app_id: String,
        ip: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    }

    /// The same record after a later release added fields to it.
    #[derive(Debug, Default, Serialize, Deserialize)]
    struct New {
        app_id: String,
        ip: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
        #[serde(default)]
        admin_port_policy: Option<u32>,
        #[serde(default)]
        labels: BTreeMap<String, String>,
    }

    fn stored_by_a_newer_build() -> Vec<u8> {
        rmp_serde::to_vec_named(&New {
            app_id: "app".into(),
            ip: "10.0.0.1".into(),
            note: Some("keep".into()),
            admin_port_policy: Some(7),
            labels: BTreeMap::from([("tier".to_string(), "edge".to_string())]),
        })
        .unwrap()
    }

    /// The point of the module: an older gateway rewriting a record must not
    /// silently delete what a newer peer put there.
    #[test]
    fn a_field_only_a_newer_build_knows_survives_an_older_writer() {
        let stored = stored_by_a_newer_build();

        let mut record: Old = rmp_serde::from_slice(&stored).unwrap();
        record.ip = "10.0.0.2".into();
        let encoded = rmp_serde::to_vec_named(&record).unwrap();

        let written = carry_unknown_fields::<Old>("inst/app", &stored, encoded);
        let seen_by_new: New = rmp_serde::from_slice(&written).unwrap();
        assert_eq!(
            seen_by_new.ip, "10.0.0.2",
            "the writer's own change applies"
        );
        assert_eq!(seen_by_new.admin_port_policy, Some(7));
        assert_eq!(seen_by_new.labels["tier"], "edge");
        // And the result is still a record the writer itself can read back.
        assert_eq!(
            rmp_serde::from_slice::<Old>(&written).unwrap().ip,
            "10.0.0.2"
        );
    }

    /// Deciding "unknown" from the keys missing in the new encoding rather than
    /// from what the type declares would undo a deliberate clear: `note` is
    /// skipped when it is `None`, so it is absent from the encoding for the same
    /// reason a field from the future is.
    #[test]
    fn a_field_this_build_declares_is_not_resurrected() {
        let stored = stored_by_a_newer_build();

        let mut record: Old = rmp_serde::from_slice(&stored).unwrap();
        assert_eq!(record.note.as_deref(), Some("keep"));
        record.note = None;
        let encoded = rmp_serde::to_vec_named(&record).unwrap();

        let written = carry_unknown_fields::<Old>("inst/app", &stored, encoded);
        let seen_by_new: New = rmp_serde::from_slice(&written).unwrap();
        assert_eq!(seen_by_new.note, None, "the clear must stick");
        assert_eq!(
            seen_by_new.admin_port_policy,
            Some(7),
            "unknowns still carried"
        );
    }

    /// Anything that is not a string-keyed map is left exactly as encoded: a
    /// scalar, and the positional array encoding that older releases wrote
    /// before values became named maps.
    #[test]
    fn a_value_that_is_not_a_string_keyed_map_is_left_alone() {
        let encoded = rmp_serde::to_vec_named(&Old::default()).unwrap();
        for stored in [
            rmp_serde::to_vec_named(&42u64).unwrap(),
            rmp_serde::to_vec_named(&"up").unwrap(),
            rmp_serde::to_vec(&New::default()).unwrap(),
            b"not msgpack at all".to_vec(),
            Vec::new(),
        ] {
            let written = carry_unknown_fields::<Old>("inst/app", &stored, encoded.clone());
            assert_eq!(
                written, encoded,
                "stored {stored:?} must not change the write"
            );
        }

        // The same holds when it is the value being written that is a scalar.
        let scalar = rmp_serde::to_vec_named(&7u64).unwrap();
        let stored = stored_by_a_newer_build();
        assert_eq!(
            carry_unknown_fields::<u64>("conn/app/1", &stored, scalar.clone()),
            scalar
        );
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct Flattened {
        a: u8,
        #[serde(flatten)]
        rest: BTreeMap<String, u8>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    enum Tagged {
        Cloudflare { api_token: String },
        Route53 { access_key: String },
    }

    /// The probe must refuse every shape whose fields it cannot enumerate.
    /// An internally tagged enum is the dangerous one: its variants have
    /// disjoint fields, so merging across a variant change would graft one
    /// variant's secrets onto another.
    #[test]
    fn a_type_the_probe_cannot_enumerate_declines_the_merge() {
        assert_eq!(
            declared_fields::<Old>(),
            Some(&["app_id", "ip", "note"][..])
        );
        assert_eq!(declared_fields::<Flattened>(), None);
        assert_eq!(declared_fields::<Tagged>(), None);
        assert_eq!(declared_fields::<u64>(), None);
        assert_eq!(declared_fields::<Vec<u8>>(), None);
        assert_eq!(declared_fields::<Option<Old>>(), None);
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Strict {
        app_id: String,
        ip: String,
    }

    /// The declared field list says which names `T` knows, not what it tolerates
    /// beside them. Carrying a field into a `deny_unknown_fields` type would
    /// leave a record its own writer can no longer decode — strictly worse than
    /// the field being dropped, which is the failure this module already
    /// accepts everywhere else.
    #[test]
    fn a_merge_that_would_not_read_back_is_abandoned() {
        let stored = stored_by_a_newer_build();
        let encoded = rmp_serde::to_vec_named(&Strict {
            app_id: "app".into(),
            ip: "10.0.0.2".into(),
        })
        .unwrap();

        let written = carry_unknown_fields::<Strict>("inst/app", &stored, encoded.clone());
        assert_eq!(
            written, encoded,
            "the write must stay decodable by its writer"
        );
        rmp_serde::from_slice::<Strict>(&written).expect("writer reads its own record");
    }

    /// A `BTreeMap` value and an externally tagged enum both encode as maps, so
    /// the byte walker alone cannot tell them apart from a struct: carrying a
    /// "missing" key into a map would resurrect an entry that was deliberately
    /// removed, and into an enum it would graft one variant's fields onto
    /// another. The declared-field probe is what refuses them.
    #[test]
    fn map_shaped_values_that_are_not_structs_are_refused() {
        #[derive(Debug, Serialize, Deserialize)]
        enum Tagless {
            Cloudflare { api_token: String },
            Route53 { access_key: String },
        }

        let stored_map = rmp_serde::to_vec_named(&BTreeMap::from([
            ("keep".to_string(), 1u8),
            ("drop".to_string(), 2u8),
        ]))
        .unwrap();
        assert!(
            matches!(stored_map[0], 0x80..=0x8f),
            "the fixture must be a map on the wire for this test to mean anything"
        );

        let encoded =
            rmp_serde::to_vec_named(&BTreeMap::from([("keep".to_string(), 1u8)])).unwrap();
        assert_eq!(
            carry_unknown_fields::<BTreeMap<String, u8>>("inst/app", &stored_map, encoded.clone()),
            encoded,
            "a removed map entry must stay removed"
        );

        let stored_enum = rmp_serde::to_vec_named(&Tagless::Cloudflare {
            api_token: "secret".into(),
        })
        .unwrap();
        let encoded = rmp_serde::to_vec_named(&Tagless::Route53 {
            access_key: "key".into(),
        })
        .unwrap();
        assert_eq!(
            carry_unknown_fields::<Tagless>("dns_cred/x", &stored_enum, encoded.clone()),
            encoded,
            "one variant's fields must not follow a change of variant"
        );
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct Renamed {
        #[serde(rename = "app")]
        app_id: String,
        #[serde(alias = "old_ip")]
        ip: String,
    }

    /// A renamed field is declared under its wire name, and an alias counts as
    /// declared too — otherwise a record written under the alias would be
    /// carried forward next to the canonical key and then fail to decode as a
    /// duplicate field.
    #[test]
    fn renames_and_aliases_count_as_declared() {
        assert_eq!(
            declared_fields::<Renamed>(),
            Some(&["app", "ip", "old_ip"][..])
        );
    }

    /// Records keep unknown fields; snapshots must not, or an older gateway
    /// would describe the certificate it just issued with the previous one's
    /// fields.
    #[test]
    fn only_long_lived_records_carry_unknown_fields() {
        for key in [
            keys::inst("app"),
            keys::node_info(1),
            keys::dns_cred("cred"),
            keys::zt_domain_config("a.example"),
            keys::GLOBAL_CERTBOT_CONFIG.to_string(),
        ] {
            assert!(is_long_lived_record(&key), "{key} is a record");
        }

        for key in [
            keys::cert_data("a.example"),
            keys::cert_lock("a.example"),
            keys::cert_attestation_latest("a.example"),
            keys::cert_attestation_history("a.example", 1),
            keys::node_status(1),
            keys::conn("app", 1),
            keys::handshake("app", 1),
            keys::last_seen_node(1, 2),
            keys::peer_addr(1),
            keys::DNS_CRED_DEFAULT.to_string(),
            keys::GLOBAL_ACME_CREDENTIALS.to_string(),
            keys::GLOBAL_ACME_ATTESTATION.to_string(),
            keys::GLOBAL_ACME_ROTATION_LOCK.to_string(),
        ] {
            assert!(!is_long_lived_record(&key), "{key} is a snapshot");
        }
    }

    /// A map with more than 15 entries needs a wider header than the one it
    /// started with, so the rewrite has to widen it rather than patch the
    /// original byte.
    #[test]
    fn the_map_header_widens_when_the_field_count_outgrows_it() {
        let wide: BTreeMap<String, u8> = (0..15).map(|i| (format!("f{i}"), i as u8)).collect();
        let stored = rmp_serde::to_vec_named(&wide).unwrap();
        assert_eq!(stored[0], 0x8f, "15 fields still fit a fixmap");

        let encoded = rmp_serde::to_vec_named(&Old::default()).unwrap();
        let written = carry_unknown_fields::<Old>("inst/app", &stored, encoded);
        assert_eq!(written[0], 0xde, "17 fields need a map16 header");
        assert_eq!(split_map(&written).unwrap().1.len(), 15 + 2);
    }

    // ---- differential tests against a full msgpack decoder ----

    fn random_value(rng: &mut impl Rng, depth: u32) -> rmpv::Value {
        let leaves = 9;
        let arms = if depth == 0 { leaves } else { leaves + 3 };
        match rng.gen_range(0..arms) {
            0 => rmpv::Value::Nil,
            1 => rmpv::Value::Boolean(rng.gen()),
            2 => rmpv::Value::from(rng.gen::<u64>()),
            3 => rmpv::Value::from(rng.gen::<i64>()),
            4 => rmpv::Value::from(rng.gen::<f32>()),
            5 => rmpv::Value::from(rng.gen::<f64>()),
            // Long enough to reach the str16/str32 and bin16/bin32 headers.
            6 => rmpv::Value::from("x".repeat(rng.gen_range(0..70_000))),
            7 => rmpv::Value::Binary(vec![7; rng.gen_range(0..70_000)]),
            8 => rmpv::Value::Ext(rng.gen(), vec![9; rng.gen_range(0..20)]),
            9 => rmpv::Value::Array(
                (0..rng.gen_range(0..18))
                    .map(|_| random_value(rng, depth - 1))
                    .collect(),
            ),
            10 => rmpv::Value::Map(
                (0..rng.gen_range(0..18))
                    .map(|_| (random_value(rng, depth - 1), random_value(rng, depth - 1)))
                    .collect(),
            ),
            _ => rmpv::Value::from(rng.gen_range(-32i8..0)),
        }
    }

    /// The skipper walks the format by hand, so it is only trustworthy if it
    /// lands on exactly the same byte a real decoder does — for every header
    /// width, not just the compact ones a struct usually produces.
    #[test]
    fn skipping_a_value_lands_where_a_real_decoder_lands() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        for case in 0..2_000 {
            let value = random_value(&mut rng, 4);
            let mut buf = Vec::new();
            rmpv::encode::write_value(&mut buf, &value).unwrap();
            assert_eq!(skip_value(&buf, 0), Some(buf.len()), "case {case}");
        }
    }

    /// The stored bytes arrive over the network, so corruption is the expected
    /// input, not the exceptional one. Whatever the skipper accepts, a real
    /// decoder must accept identically; whatever it rejects must be genuinely
    /// undecodable.
    #[test]
    fn corrupted_encodings_are_judged_the_same_way_a_real_decoder_judges_them() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(23);
        let mut accepted = 0u32;
        for _ in 0..50_000 {
            let value = random_value(&mut rng, 3);
            let mut buf = Vec::new();
            rmpv::encode::write_value(&mut buf, &value).unwrap();
            if buf.is_empty() || buf.len() > 4096 {
                continue;
            }
            for _ in 0..rng.gen_range(1..4) {
                let at = rng.gen_range(0..buf.len());
                buf[at] ^= 1 << rng.gen_range(0..8);
            }
            if rng.gen_range(0..3) == 0 {
                buf.truncate(rng.gen_range(0..buf.len()));
            }

            let mine = skip_value(&buf, 0);
            let mut cursor = &buf[..];
            let theirs = rmpv::decode::read_value(&mut cursor)
                .ok()
                .map(|_| buf.len() - cursor.len());
            match (mine, theirs) {
                (Some(mine), Some(theirs)) => {
                    accepted += 1;
                    assert_eq!(mine, theirs, "length disagreement on {buf:?}");
                }
                (Some(mine), None) => panic!("accepted {mine} bytes rmpv rejects: {buf:?}"),
                (None, Some(_)) => {
                    assert!(buf.contains(&0xc1), "rejected what rmpv accepts: {buf:?}")
                }
                (None, None) => {}
            }
        }
        assert!(
            accepted > 1_000,
            "corpus degenerate: only {accepted} accepted"
        );
    }

    /// Nothing about the stored bytes is guaranteed, so no input may read past
    /// the buffer, panic, or claim more than it was given.
    #[test]
    fn arbitrary_bytes_are_never_over_read() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(11);
        for _ in 0..100_000 {
            let buf: Vec<u8> = (0..rng.gen_range(0..40)).map(|_| rng.gen()).collect();
            if let Some(end) = skip_value(&buf, 0) {
                assert!(end <= buf.len());
            }
            if let Some((_, fields)) = split_map(&buf) {
                for field in fields {
                    assert!(field.raw.len() <= buf.len());
                }
            }
        }
    }

    /// A nested value deep enough to exhaust a recursive walker must still be
    /// handled, since a peer's record is not bounded by what this node writes.
    #[test]
    fn deep_nesting_does_not_exhaust_the_stack() {
        let deep: Vec<u8> = std::iter::repeat_n(0x91, 200_000).chain([0xc0]).collect();
        assert_eq!(skip_value(&deep, 0), Some(deep.len()));
    }

    /// A header that claims more entries than the buffer could possibly hold is
    /// the cheap way to make a parser allocate or spin.
    #[test]
    fn a_header_claiming_more_than_the_buffer_holds_is_refused() {
        assert_eq!(skip_value(&[0xdf, 0xff, 0xff, 0xff, 0xff], 0), None);
        assert_eq!(skip_value(&[0xdd, 0xff, 0xff, 0xff, 0xff], 0), None);
        assert_eq!(skip_value(&[0xdb, 0xff, 0xff, 0xff, 0xff], 0), None);
        assert_eq!(
            skip_value(&[0xc1], 0),
            None,
            "the reserved marker is not a value"
        );
        assert!(split_map(&[0xdf, 0xff, 0xff, 0xff, 0xff]).is_none());
    }
}
