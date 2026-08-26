// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! The persistent DNS authorization record used by the `dns-persist-01` challenge.
//!
//! `dns-persist-01` (draft-ietf-acme-dns-persist-01) replaces the per-order
//! `_acme-challenge` TXT record of `dns-01` with a single record that stays in the
//! zone: `_validation-persist.<name>`, naming the CA and the ACME account allowed
//! to issue for that name. The account key proves who is asking; the record proves
//! the zone owner agreed. Nothing about it changes between orders, so a client that
//! uses this method never needs write access to the zone.
//!
//! This module owns the record's syntax: rendering the line an operator has to
//! publish, and deciding whether what is currently published would satisfy the CA.
//! The RDATA is an RFC 8659 `issue-value` — the same grammar as a CAA `issue`
//! record — so the parser here mirrors the one CAs run (see `va/dns_persist.go` in
//! Boulder), including the parts that reject rather than ignore: a trailing
//! semicolon, a repeated tag, whitespace inside a value.

use std::fmt;

use anyhow::{bail, Context, Result};

/// Label prepended to the name being validated to form the validation domain name.
///
/// draft-ietf-acme-dns-persist-01, section 4.
const VALIDATION_LABEL: &str = "_validation-persist";

/// Issuer Domain Name for Let's Encrypt, matching the `caaIdentities` it advertises.
///
/// A CA lists the names it answers to in the challenge object's
/// `issuer-domain-names`; a record naming anything else is ignored by that CA.
pub const LETS_ENCRYPT_ISSUER_DOMAIN_NAME: &str = "letsencrypt.org";

/// The Issuer Domain Name to use, given what an operator configured.
///
/// Empty means the default, which is what an untouched configuration carries.
/// Anything else is checked before it is believed: the name is interpolated
/// straight into an RFC 8659 `issue-value`, both in a `_validation-persist`
/// record and in the CAA records certbot publishes, and `set_caa_records`
/// installs the new value *after* deleting the records it replaces. A value
/// carrying a `;`, a space, or a `#` does not merely fail to authorize -- it
/// leaves the zone holding a malformed `issue` property with no valid record
/// behind it, which is CAA that forbids every issuer. Rejecting it at the point
/// it is configured keeps that out of the zone entirely.
pub fn resolve_issuer_domain_name(configured: &str) -> Result<String> {
    let name = configured.trim();
    if name.is_empty() {
        return Ok(LETS_ENCRYPT_ISSUER_DOMAIN_NAME.to_string());
    }
    let name = name.trim_end_matches('.');
    if name.is_empty() || name.len() > 253 {
        bail!("issuer domain name must be between 1 and 253 characters: {configured:?}");
    }
    for label in name.split('.') {
        // RFC 8659 spells a label `(ALPHA / DIGIT) *( *("-") (ALPHA / DIGIT) )`:
        // alphanumeric at both ends, hyphens only between them, and nothing
        // else -- no underscore, which is a DNS convention for names that are
        // never issuer names. A CA holding the record to that grammar reads
        // anything looser as a malformed `issue` property, which is the state
        // this check exists to keep out of a zone.
        // Each rejection names what it rejected: the operator has to fix the
        // value, and "malformed" alone does not say which character to remove --
        // an underscore, say, which is legal in plenty of DNS names and is the
        // one most likely to be reached for here.
        let bytes = label.as_bytes();
        let context = "it is written verbatim into CAA and validation records, \
                       where a malformed label makes the whole record unparseable";
        if bytes.is_empty() {
            bail!("issuer domain name {configured:?} has an empty label: {context}");
        }
        if bytes.len() > 63 {
            bail!("issuer domain name {configured:?} has a label over 63 octets: {context}");
        }
        // Scanned as characters, not bytes: a byte cast to `char` renders a
        // multi-byte character's first byte as some unrelated Latin-1 one, so
        // `lé.org` would be rejected for a `Ã` that appears nowhere in the
        // value the same message quotes back.
        if let Some(ch) = label
            .chars()
            .find(|ch| !ch.is_ascii_alphanumeric() && *ch != '-')
        {
            bail!(
                "issuer domain name {configured:?} contains {ch:?}, which a DNS label cannot: \
                 {context}"
            );
        }
        if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
            bail!(
                "issuer domain name {configured:?} has a label starting or ending with a \
                 hyphen: {context}"
            );
        }
    }
    Ok(name.to_string())
}

/// The `policy` value that widens a record to cover wildcards.
const POLICY_WILDCARD: &str = "wildcard";

/// The validation domain name for `name`, where the CA looks for the TXT record.
///
/// A wildcard request is authorized by the record on its base name: ACME strips the
/// `*.` before creating the authorization, so `*.example.com` and `example.com`
/// share `_validation-persist.example.com` and are told apart by `policy=wildcard`.
pub fn validation_domain(name: &str) -> String {
    let base = name.strip_prefix("*.").unwrap_or(name);
    format!("{VALIDATION_LABEL}.{base}")
}

/// The record an operator has to publish for one name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRecord {
    /// Issuer Domain Name of the CA this record authorizes.
    pub issuer_domain_name: String,
    /// URI of the ACME account allowed to issue, compared byte for byte by the CA.
    pub account_uri: String,
    /// Whether the record also covers `*.<name>`.
    pub wildcard: bool,
}

impl AuthorizationRecord {
    /// The TXT RDATA to publish, as a single string.
    ///
    /// Rendered without a trailing semicolon: CAs read the RDATA as an RFC 8659
    /// `issue-value`, where a trailing semicolon is an empty parameter and makes
    /// the whole record malformed.
    pub fn rdata(&self) -> String {
        let mut rdata = format!(
            "{}; accounturi={}",
            self.issuer_domain_name, self.account_uri
        );
        if self.wildcard {
            rdata.push_str("; policy=wildcard");
        }
        rdata
    }

    /// Whether `rdata` currently published at the validation domain satisfies this
    /// record's requirement, as of `now` (UNIX seconds).
    ///
    /// Follows the CA's own filter: a record naming a different issuer is not a
    /// failure, it belongs to another CA and is skipped. Only a record that names
    /// our issuer is held to the account, policy and lifetime checks.
    fn satisfied_by(&self, rdata: &str, now: u64) -> bool {
        let Ok(parsed) = IssueValue::parse(rdata) else {
            return false;
        };
        if normalized_issuer(&parsed.issuer_domain_name)
            != normalized_issuer(&self.issuer_domain_name)
        {
            return false;
        }
        if parsed.account_uri != self.account_uri {
            return false;
        }
        if parsed.persist_until.is_some_and(|until| now > until) {
            return false;
        }
        // A record without `policy=wildcard` authorizes the exact name only, so it
        // cannot stand in for a wildcard request. The reverse is fine: a wildcard
        // record also covers the name itself.
        !self.wildcard || parsed.policy.as_deref().is_some_and(is_wildcard_policy)
    }

    /// Whether any of the TXT records at the validation domain satisfies this one.
    ///
    /// Several records may sit at the same label, one per CA or per account, and
    /// the CA accepts the name if any single record passes.
    pub fn satisfied_by_any(&self, published: &[String], now: u64) -> bool {
        published.iter().any(|rdata| self.satisfied_by(rdata, now))
    }
}

impl fmt::Display for AuthorizationRecord {
    /// Renders the full zone-file line, ready to paste into a DNS provider.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IN TXT \"{}\"", self.rdata())
    }
}

/// A parsed RFC 8659 `issue-value`, the grammar shared with CAA `issue` records.
#[derive(Debug, PartialEq, Eq)]
struct IssueValue {
    issuer_domain_name: String,
    account_uri: String,
    policy: Option<String>,
    /// UNIX timestamp after which the CA stops accepting the record.
    persist_until: Option<u64>,
}

impl IssueValue {
    fn parse(rdata: &str) -> Result<Self> {
        let mut parts = rdata.split(';');
        let issuer_domain_name = trim_wsp(parts.next().unwrap_or_default());
        if issuer_domain_name.is_empty() {
            bail!("missing issuer domain name");
        }

        let mut account_uri = None;
        let mut policy = None;
        let mut persist_until = None;
        let mut seen = Vec::new();
        for part in parts {
            let part = trim_wsp(part);
            // An empty parameter means a doubled or trailing semicolon. CAs treat
            // that as malformed rather than skipping it, so neither do we.
            if part.is_empty() {
                bail!("empty parameter or trailing semicolon");
            }
            let (tag, value) = part.split_once('=').context("parameter is not tag=value")?;
            // RFC 8659's grammar is `parameter = tag *WSP "=" *WSP value`, so the
            // separator may be padded on either side and each half is trimmed on
            // its own. Trimming only the whole parameter would read the tag of
            // `accounturi = <uri>` as `"accounturi "` and report the mandatory
            // parameter missing on a record the CA accepts.
            let tag = trim_wsp(tag).to_lowercase();
            let value = trim_wsp(value);
            if tag.is_empty() {
                bail!("parameter has an empty tag");
            }
            if !value.bytes().all(is_value_byte) {
                bail!("parameter {tag} has a value with a forbidden character");
            }
            match tag.as_str() {
                "accounturi" | "policy" | "persistuntil" => {
                    // Only recognized tags are held to uniqueness: the draft has
                    // the CA ignore unknown tags outright, so a record repeating
                    // one is still a record the CA issues from.
                    if seen.contains(&tag) {
                        bail!("duplicate parameter {tag}");
                    }
                    seen.push(tag.clone());
                }
                // The draft requires unrecognized tags to be ignored, so that
                // later revisions can add parameters without invalidating records.
                _ => continue,
            }
            match tag.as_str() {
                "accounturi" => {
                    if value.is_empty() {
                        bail!("empty value for the mandatory accounturi parameter");
                    }
                    account_uri = Some(value.to_string());
                }
                "policy" => policy = Some(value.to_string()),
                "persistuntil" => {
                    persist_until = Some(
                        value
                            .parse::<u64>()
                            .context("persistUntil is not a base-10 timestamp")?,
                    )
                }
                _ => {}
            }
        }

        Ok(Self {
            issuer_domain_name: issuer_domain_name.to_string(),
            account_uri: account_uri.context("missing mandatory accounturi parameter")?,
            policy,
            persist_until,
        })
    }
}

/// An Issuer Domain Name folded the way the CA folds it before comparing.
///
/// Boulder normalizes both sides (lowercase, then drop the root dot) before
/// deciding whether a record is one of its own, so `LetsEncrypt.ORG.` names the
/// same CA as `letsencrypt.org`. Comparing raw bytes here would treat a record
/// the CA honours as belonging to someone else and warn about a missing record
/// through every issuance. IDNA folding is left out: this compares against a
/// name dstack configures, and an operator writing a non-ASCII issuer name has
/// a mismatch a self-check cannot paper over.
fn normalized_issuer(name: &str) -> String {
    name.trim_end_matches('.').to_lowercase()
}

fn is_wildcard_policy(policy: &str) -> bool {
    policy.eq_ignore_ascii_case(POLICY_WILDCARD)
}

/// Trim the whitespace RFC 8659 allows around the issuer name and each parameter.
fn trim_wsp(part: &str) -> &str {
    part.trim_matches([' ', '\t'])
}

/// Whether a byte may appear in a parameter value.
///
/// RFC 8659 allows printable ASCII except `;`, which excludes whitespace: a value
/// containing a space is a malformed record, not a value with a space in it.
fn is_value_byte(byte: u8) -> bool {
    matches!(byte, 0x21..=0x3a | 0x3c..=0x7e)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An arbitrary "now" that precedes every `persistUntil` used below.
    const NOW: u64 = 1_700_000_000;
    const ACCOUNT: &str = "https://acme-v02.api.letsencrypt.org/acme/acct/1234567890";

    fn record(wildcard: bool) -> AuthorizationRecord {
        AuthorizationRecord {
            issuer_domain_name: LETS_ENCRYPT_ISSUER_DOMAIN_NAME.to_string(),
            account_uri: ACCOUNT.to_string(),
            wildcard,
        }
    }

    /// Whether `published` satisfies a request for `name`, wildcard or not.
    fn accepts(wildcard: bool, published: &str) -> bool {
        record(wildcard).satisfied_by(published, NOW)
    }

    /// RFC 8659 spells the parameter grammar `tag *WSP "=" *WSP value`, and
    /// Boulder trims each half separately. A record padded around the separator
    /// is one the CA issues from, so the self-check has to read it the same way.
    #[test]
    fn whitespace_around_the_separator_is_not_part_of_the_tag_or_value() {
        assert!(accepts(
            false,
            &format!("letsencrypt.org; accounturi = {ACCOUNT}")
        ));
        assert!(accepts(
            true,
            &format!("letsencrypt.org;\taccounturi\t=\t{ACCOUNT}; policy\t=\twildcard")
        ));
    }

    /// The draft has the CA ignore unrecognized tags outright, so repeating one
    /// cannot invalidate a record. Uniqueness is only enforced where the CA
    /// enforces it.
    #[test]
    fn a_repeated_unknown_tag_is_ignored_rather_than_fatal() {
        assert!(accepts(
            false,
            &format!("letsencrypt.org; accounturi={ACCOUNT}; futuretag=a; futuretag=b")
        ));
        assert!(!accepts(
            false,
            &format!("letsencrypt.org; accounturi={ACCOUNT}; accounturi={ACCOUNT}")
        ));
    }

    /// Boulder folds case and drops the root dot before deciding whether a
    /// record names it, so the same record must not read as another CA's here.
    #[test]
    fn the_issuer_name_is_compared_the_way_the_ca_compares_it() {
        assert!(accepts(
            false,
            &format!("LetsEncrypt.ORG.; accounturi={ACCOUNT}")
        ));
        assert!(!accepts(
            false,
            &format!("other-ca.example; accounturi={ACCOUNT}")
        ));
    }

    /// `accounturi` is mandatory, and an empty value does not supply it.
    #[test]
    fn an_empty_account_uri_is_not_an_account_uri() {
        assert!(!accepts(false, "letsencrypt.org; accounturi="));
    }

    /// A label longer than DNS allows is refused, and one right at the limit is
    /// not: the bound is the protocol's, not a guess.
    #[test]
    fn a_label_is_held_to_its_dns_length() {
        let sixty_three = "a".repeat(63);
        assert!(resolve_issuer_domain_name(&format!("{sixty_three}.org")).is_ok());
        assert!(resolve_issuer_domain_name(&format!("{sixty_three}a.org")).is_err());
    }

    /// A rejection has to say what to change: the character it objected to, not
    /// just that the value was wrong.
    #[test]
    fn a_rejection_names_the_character_it_rejected() {
        let err = resolve_issuer_domain_name("my_ca.example.com")
            .expect_err("an underscore is not a DNS label character");
        assert!(err.to_string().contains('_'), "{err:#}");

        // A multi-byte character has to name itself. Scanning bytes and casting
        // to `char` would report the first byte of `é` as `Ã`, which does not
        // occur in the value the same message quotes back.
        let err = resolve_issuer_domain_name("lé.org").expect_err("é is not a DNS label character");
        assert!(err.to_string().contains('é'), "{err:#}");
        assert!(!err.to_string().contains('Ã'), "{err:#}");
    }

    /// Empty is what an untouched configuration carries, and it means the
    /// default rather than a name of zero length -- which as an `issue-value`
    /// would be CAA denying every issuer.
    #[test]
    fn an_unset_issuer_name_is_the_default_one() {
        assert_eq!(
            resolve_issuer_domain_name("").unwrap(),
            LETS_ENCRYPT_ISSUER_DOMAIN_NAME
        );
        assert_eq!(
            resolve_issuer_domain_name("   ").unwrap(),
            LETS_ENCRYPT_ISSUER_DOMAIN_NAME
        );
        assert_eq!(
            resolve_issuer_domain_name("pebble.letsencrypt.org.").unwrap(),
            "pebble.letsencrypt.org"
        );
    }

    /// The name is interpolated into records that a `;` or a space makes
    /// malformed, and CAA is rewritten by deleting the old records first, so a
    /// typo accepted here is a zone that forbids all issuance.
    #[test]
    fn a_name_that_would_corrupt_a_record_is_refused() {
        for bad in [
            "lets encrypt.org",
            "letsencrypt.org;policy=wildcard",
            "#letsencrypt.org",
            "letsencrypt..org",
            "\"letsencrypt.org\"",
            // RFC 8659's label grammar bounds both ends of a label, so these
            // are as unparseable to a strict CA as a space is.
            "_letsencrypt.org",
            "-letsencrypt.org",
            "letsencrypt-.org",
            "lé.org",
        ] {
            assert!(
                resolve_issuer_domain_name(bad).is_err(),
                "{bad:?} should be refused"
            );
        }
    }

    #[test]
    fn validation_domain_prepends_the_label() {
        assert_eq!(
            validation_domain("example.com"),
            "_validation-persist.example.com"
        );
    }

    #[test]
    fn validation_domain_strips_the_wildcard_prefix() {
        // The CA looks up the base name for a wildcard authorization, so a record
        // at `_validation-persist.*.example.com` would never be read.
        assert_eq!(
            validation_domain("*.example.com"),
            "_validation-persist.example.com"
        );
    }

    #[test]
    fn rdata_has_no_trailing_semicolon() {
        assert_eq!(
            record(false).rdata(),
            format!("letsencrypt.org; accounturi={ACCOUNT}")
        );
    }

    #[test]
    fn rdata_carries_the_wildcard_policy() {
        assert_eq!(
            record(true).rdata(),
            format!("letsencrypt.org; accounturi={ACCOUNT}; policy=wildcard")
        );
    }

    #[test]
    fn display_renders_a_zone_file_line() {
        assert_eq!(
            record(false).to_string(),
            format!("IN TXT \"letsencrypt.org; accounturi={ACCOUNT}\"")
        );
    }

    #[test]
    fn rendered_record_parses_back() {
        for wildcard in [false, true] {
            assert!(
                accepts(wildcard, &record(wildcard).rdata()),
                "wildcard={wildcard}"
            );
        }
    }

    #[test]
    fn accepts_the_draft_example_layout() {
        // draft-ietf-acme-dns-persist-01, figure 2, plus the whitespace RFC 8659
        // allows around the issuer name and each parameter.
        let record = AuthorizationRecord {
            issuer_domain_name: "authority.example".to_string(),
            account_uri: "https://ca.example/acct/123".to_string(),
            wildcard: false,
        };
        for published in [
            "authority.example; accounturi=https://ca.example/acct/123",
            "authority.example;accounturi=https://ca.example/acct/123",
            "\tauthority.example ;\taccounturi=https://ca.example/acct/123 ",
        ] {
            assert!(record.satisfied_by(published, NOW), "{published:?}");
        }
    }

    #[test]
    fn matches_tags_case_insensitively() {
        assert!(accepts(
            true,
            &format!("letsencrypt.org; AccountURI={ACCOUNT}; Policy=WILDCARD")
        ));
    }

    #[test]
    fn rejects_a_different_account_uri() {
        assert!(!accepts(
            false,
            "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/9"
        ));
    }

    #[test]
    fn compares_the_account_uri_without_case_folding() {
        // The draft pins Simple String Comparison, so an upper-cased URI is a
        // different account as far as the CA is concerned.
        assert!(!accepts(
            false,
            &format!("letsencrypt.org; accounturi={}", ACCOUNT.to_uppercase())
        ));
    }

    #[test]
    fn ignores_a_record_naming_another_issuer() {
        assert!(!accepts(
            false,
            &format!("otherca.example; accounturi={ACCOUNT}")
        ));
    }

    #[test]
    fn rejects_a_plain_record_for_a_wildcard_request() {
        let published = record(false).rdata();
        assert!(accepts(false, &published));
        assert!(!accepts(true, &published));
    }

    #[test]
    fn accepts_a_wildcard_record_for_a_plain_request() {
        assert!(accepts(false, &record(true).rdata()));
    }

    #[test]
    fn rejects_a_trailing_semicolon() {
        // A CA reads the empty tail as an empty parameter and fails the whole
        // record, so a record rendered with one would be silently unusable.
        assert!(!accepts(
            false,
            &format!("letsencrypt.org; accounturi={ACCOUNT};")
        ));
    }

    #[test]
    fn rejects_a_duplicate_parameter() {
        assert!(!accepts(
            false,
            &format!("letsencrypt.org; accounturi={ACCOUNT}; accounturi={ACCOUNT}")
        ));
    }

    #[test]
    fn rejects_whitespace_inside_a_value() {
        assert!(!accepts(
            false,
            "letsencrypt.org; accounturi=https://ca.example/acct/1 2"
        ));
    }

    #[test]
    fn rejects_a_record_without_accounturi() {
        assert!(!accepts(false, "letsencrypt.org; policy=wildcard"));
    }

    #[test]
    fn ignores_unrecognized_parameters() {
        assert!(accepts(
            true,
            &format!("letsencrypt.org; accounturi={ACCOUNT}; policy=wildcard; futuretag=whatever")
        ));
    }

    #[test]
    fn rejects_an_expired_persist_until() {
        let published = format!("letsencrypt.org; accounturi={ACCOUNT}; persistUntil={NOW}");
        assert!(record(false).satisfied_by(&published, NOW));
        assert!(!record(false).satisfied_by(&published, NOW + 1));
    }

    #[test]
    fn rejects_a_malformed_persist_until() {
        assert!(!accepts(
            false,
            &format!("letsencrypt.org; accounturi={ACCOUNT}; persistUntil=tomorrow")
        ));
    }

    #[test]
    fn accepts_any_one_of_the_published_records() {
        let published = vec![
            "otherca.example; accounturi=https://other.example/acct/1".to_string(),
            record(true).rdata(),
        ];
        assert!(record(true).satisfied_by_any(&published, NOW));
        assert!(!record(true).satisfied_by_any(&published[..1], NOW));
    }
}
