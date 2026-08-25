# Certificate issuance without a DNS credential (`dns-persist-01`)

`dns-01` asks certbot to write a fresh `_acme-challenge` TXT record for every
order, so whatever runs certbot holds a DNS API token with write access to the
zone, forever. In dstack that token lives inside the gateway CVM. Attestation
covers what the CVM is running, but a token is a token: anything that gets hold
of it can rewrite the zone, including records that have nothing to do with
certificates.

`dns-persist-01` moves the proof out of the issuance loop. The zone owner
publishes one record naming the CA and the ACME account allowed to issue:

```dns
_validation-persist.example.com. IN TXT "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1234567890"
```

The account key proves who is asking, the record proves the zone owner agreed,
and neither changes between orders. certbot reads DNS and never writes it, so
the CVM holds no DNS credential and the zone can be hosted anywhere — no
Cloudflare account, no API token, no provider integration.

> **Experimental.** `dns-persist-01` is specified in
> [draft-ietf-acme-dns-persist-01][draft], which is still changing: an open
> working-group issue may add a client-key-derived value to the record, and
> Let's Encrypt has said it will not deploy the challenge to production until
> that is resolved. It is live on Let's Encrypt **staging** and in
> [Pebble][pebble]. Treat the record format as unstable, and expect to
> republish when the draft settles.

[draft]: https://datatracker.ietf.org/doc/html/draft-ietf-acme-dns-persist-01
[pebble]: https://github.com/letsencrypt/pebble

## What the record means

| Part | Effect |
| --- | --- |
| `letsencrypt.org` | Issuer Domain Name. A CA ignores records naming a different issuer, so one label can hold records for several CAs. |
| `accounturi=` | The ACME account authorized to issue. Compared byte for byte — no case folding, no URI normalization. |
| `policy=wildcard` | Extends the record to `*.example.com`. Without it the CA authorizes `example.com` alone and refuses wildcard orders. |
| `persistUntil=` | Optional UNIX timestamp after which the CA stops accepting the record. |

A wildcard order authorizes from its base name — `*.example.com` is validated
against `_validation-persist.example.com`, not
`_validation-persist.*.example.com` — so one record covers a name and its
wildcard.

Two things about the syntax bite in practice, because a CA rejects the whole
record rather than ignoring the offending part: **no trailing semicolon**, and
**no whitespace inside a value**. certbot renders records that satisfy both;
copy them verbatim rather than retyping.

The scope stops at the names above. Let's Encrypt does not walk up the tree, so
a record on `example.com` does not authorize `sub.example.com` — give each base
name its own record.

## Standalone certbot

`certbot` never writes DNS in this mode, so setup is: create the account, read
the records off it, publish them, then issue.

```toml
# certbot.toml
workdir = "/var/lib/certbot"
acme_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
challenge = "dns-persist-01"
issuer_domain_name = "letsencrypt.org"
# auto_set_caa promises certbot keeps CAA in sync, which it cannot do without
# write access. Leave it off and publish the CAA records below by hand.
auto_set_caa = false
domains = ["example.com", "*.example.com"]
renew_interval = 3600
renew_days_before = 10
renew_timeout = 120
max_dns_wait = 300
```

`cf_api_token` is unused and can be left out; certbot warns if one is set.

```console
$ certbot init -c certbot.toml
INFO certbot::bot: creating new ACME account
INFO certbot::bot: created new ACME account: https://acme-staging-v02.api.letsencrypt.org/acme/acct/1234567890

$ certbot dns-records -c certbot.toml
_validation-persist.example.com. IN TXT "letsencrypt.org; accounturi=https://acme-staging-v02.api.letsencrypt.org/acme/acct/1234567890; policy=wildcard"
example.com. IN CAA 0 issue "letsencrypt.org;validationmethods=dns-persist-01;accounturi=https://acme-staging-v02.api.letsencrypt.org/acme/acct/1234567890"
example.com. IN CAA 0 issuewild "letsencrypt.org;validationmethods=dns-persist-01;accounturi=https://acme-staging-v02.api.letsencrypt.org/acme/acct/1234567890"
```

Publish all three, wait for them to propagate, then issue:

```console
$ certbot renew --once -c certbot.toml
INFO certbot::acme_client: requesting new certificates for example.com, *.example.com
INFO certbot::bot: created new certificate
```

Renewals need nothing further. The record stays, and `certbot renew` reuses it
for every order.

The CAA records are optional but recommended — they stop any other account, at
Let's Encrypt or elsewhere, from being issued for your name. Note the
`validationmethods=dns-persist-01` in them: a CAA record left pinned to
`dns-01` refuses every `dns-persist-01` order, so switching methods means
updating CAA and the validation record together.

### When issuance fails

certbot checks its own resolver before starting an order, and says exactly what
it expected to find:

```
WARN certbot::acme_client: no TXT record at _validation-persist.example.com matches the expected value: letsencrypt.org; accounturi=https://acme-staging-v02.api.letsencrypt.org/acme/acct/1234567890; policy=wildcard
Error: order is invalid: API error: Checking DNS-PERSIST-01 challenge TXT record with issuer-domain-name "letsencrypt.org": accounturi mismatch: expected "https://acme-staging-v02.api.letsencrypt.org/acme/acct/1234567890", got "https://acme-staging-v02.api.letsencrypt.org/acme/acct/9876543210" (urn:ietf:params:acme:error:unauthorized)
```

The check is advisory and never blocks an order: certbot's resolver is not the
CA's, and its expectation can be stricter than what the CA would accept. A
warning with a successful issuance underneath it is a resolver difference, not
a problem. A record that genuinely does not match costs the full `max_dns_wait`
before the order is sent, because the check waits out its budget first.

If the CA rejects the order, compare the published record against
`certbot dns-records` character by character. The usual causes are a stale
`accounturi` after the account was recreated, a missing `policy=wildcard` on a
wildcard order, and an issuer domain name that does not match the CA.

## dstack-gateway

A ZT domain picks its method with the `challenge` field, which defaults to
`dns-01` — existing domains are unaffected:

```json
{ "domain": "app.example.com", "port": 443, "challenge": "dns-persist-01" }
```

Such a domain needs no `dns_cred_id`, and the gateway CVM never receives a DNS
credential for it. `GetZtDomain` and `ListZtDomains` return the records to
publish in `required_dns_records`, and the gateway logs them whenever it cannot
write DNS itself:

```
WARN cert[app.example.com]: publish this record by hand: _validation-persist.app.example.com. IN TXT "letsencrypt.org; accounturi=...; policy=wildcard"
```

The gateway issues for `*.{domain}` only, so each domain needs one validation
record with `policy=wildcard`.

A ZT domain's challenge is chosen when it is added and carried forward by every
edit, in the dashboard's ZT-Domain form as well as over the API.

For a non-production ACME server, set `issuer_domain_name` in the global certbot
config — `Admin.SetCertbotConfig`, or the field of that name in the dashboard's
Certbot Configuration — to whatever that server puts in `issuer-domain-names`,
`pebble.letsencrypt.org` for Pebble. Empty means `letsencrypt.org`. It also
names the CA in the CAA records certbot writes for `dns-01` domains, so one
setting covers both challenges rather than pinning CAA to Let's Encrypt while
orders go elsewhere.

Two operations behave differently on these domains:

- **`SetCaa`** skips them. There is nothing to reconcile without write access;
  the records are logged instead, and the summary reports how many were left to
  the operator.
- **`RotateAcmeCredentials`** is not self-service. Rotation moves the cluster
  to a new ACME account, and every `_validation-persist` record still names the
  old one, so orders for those domains fail until the operator republishes. The
  response returns the new records in `required_dns_records` and the gateway
  logs them; publish before the next renewal comes due.

## Related

- [dstack-gateway](dstack-gateway.md) — gateway architecture and TLS termination
- [deployment.md](deployment.md#4-zero-trust-https-optional) — the `dns-01` setup this replaces
