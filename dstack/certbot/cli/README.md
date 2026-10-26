# certbot

A small ACME client that issues and renews certificates over dns-01, with Cloudflare
as the DNS provider. It is a testing and development tool: it exercises the `certbot`
crate that dstack-gateway builds on, and it obtains a certificate by hand for a local
or staging setup.

It is not the production path. A deployed gateway issues its own certificates from the
domain configuration and DNS credentials it already holds, publishes the resulting
public keys over `/acme-info` for `ct_monitor` to check the CT logs against, and — when
that gateway runs in a CVM — keeps both the ACME account key and the certificate key
inside the enclave. This CLI keeps them in a plain directory on whatever host runs it,
so nothing about the issuance is attested and the key is only as protected as that
filesystem. Point it at Pebble or Let's Encrypt staging while working on the ACME code,
not at the certificate fronting a real deployment.

## Usage

Write a configuration template, fill in the Cloudflare token and the names, then run
the daemon:

```bash
certbot cfg --write-to certbot.toml
$EDITOR certbot.toml
RUST_LOG=info,certbot=debug certbot renew -c certbot.toml
```

`renew` issues a certificate if none is live, reissues when the live one does not carry
the configured `domains`, and renews once the live one is within `renew_days_before` of
expiry. It loops every `renew_interval` seconds; `--once` runs a single pass and exits,
and `--force` renews whether or not expiry is near.

`init` creates the ACME account — and, with `auto_set_caa`, the CAA records — without
issuing anything. `set-caa` writes the CAA records for the configured names on their
own, which is worth running after adding a name to `domains`: the automatic pass only
happens when the account is created.

## Configuration

`certbot cfg` prints every field with its documentation. Two optional fields are absent
from that template because they default to nothing:

- `cf_api_url` — a Cloudflare-compatible API base URL, for pointing the DNS calls at a
  mock server instead of Cloudflare.
- `renewed_hook` — a shell command run after a certificate is committed, e.g. to reload
  whatever is serving it.

`workdir` holds everything else. Each issuance lands in its own timestamped directory
under `backup/`, `live/cert.pem` and `live/key.pem` are symlinks to the one in force,
and the ACME account credentials sit in `credentials.json`. Editing `domains` takes
effect on the next run: the live certificate's names are compared against the
configuration, and a mismatch reissues.
