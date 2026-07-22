# Test `dstackup image pull` with a local release API

`--release-api-base-url` accepts plain HTTP URLs, including localhost. A small
GitHub Releases API overlay is included for local testing. Locally published
releases shadow GitHub; API requests that are not present locally are relayed to
`https://api.github.com`.

Start it:

```bash
./tools/mock-github-releases.py --port 8000
```

Publish a release and copy a local tarball into the mock asset store. The mock
calculates and publishes its SHA-256 digest automatically:

```bash
curl -fsS -X POST \
  http://localhost:8000/__admin/repos/Dstack-TEE/dstack/releases \
  -H 'content-type: application/json' \
  -d '{
    "tag_name": "guest-os-v99.0.0",
    "assets": [{"local_path": "/tmp/dstack-99.0.0.tar.gz"}]
  }'
```

Pull the locally published latest release:

```bash
sudo dstackup image pull \
  --release-api-base-url http://localhost:8000/repos \
  --force
```

A release can instead reference an already hosted asset by supplying `name`,
`browser_download_url`, and optionally `digest` in the asset object. State is
in memory and resets when the mock exits; copied assets remain in `--asset-dir`.
GitHub API rate limits still apply to relayed requests. Set an `Authorization`
header on a direct request to the mock when testing authenticated relays.
