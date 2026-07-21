#!/usr/bin/env python3
"""Local GitHub Releases API overlay for dstackup development.

Locally published releases shadow GitHub. Requests not satisfied locally are
relayed to https://api.github.com. Release assets can be copied into --asset-dir
by specifying an asset's "local_path" in the publish request.
"""

import argparse
import hashlib
import json
import mimetypes
import shutil
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

UPSTREAM = "https://api.github.com"


class State:
    def __init__(self, asset_dir: Path):
        self.asset_dir = asset_dir.resolve()
        self.asset_dir.mkdir(parents=True, exist_ok=True)
        self.releases = {}  # repo -> tag -> release; insertion order is newest first

    def publish(self, repo, release, public_base):
        tag = release.get("tag_name")
        if not isinstance(tag, str) or not tag:
            raise ValueError("tag_name must be a non-empty string")
        assets = []
        for source in release.get("assets", []):
            asset = dict(source)
            local_path = asset.pop("local_path", None)
            if local_path:
                src = Path(local_path).resolve(strict=True)
                name = asset.get("name") or src.name
                if Path(name).name != name:
                    raise ValueError(f"unsafe asset name: {name!r}")
                dst = self.asset_dir / name
                shutil.copyfile(src, dst)
                digest = hashlib.sha256(dst.read_bytes()).hexdigest()
                asset.update(
                    name=name,
                    browser_download_url=f"{public_base}/__assets/{name}",
                    digest=f"sha256:{digest}",
                )
            if not asset.get("name") or not asset.get("browser_download_url"):
                raise ValueError("each asset needs name and browser_download_url, or local_path")
            assets.append(asset)
        release = dict(release, assets=assets)
        releases = self.releases.setdefault(repo, {})
        releases.pop(tag, None)
        self.releases[repo] = {tag: release, **releases}
        return release


class Handler(BaseHTTPRequestHandler):
    server_version = "dstack-release-mock/1"

    def json_response(self, status, value):
        body = json.dumps(value, indent=2).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        # POST /__admin/repos/{owner}/{repo}/releases
        parts = self.path.strip("/").split("/")
        if len(parts) != 5 or parts[:2] != ["__admin", "repos"] or parts[4:] != ["releases"]:
            self.send_error(404)
            return
        try:
            size = int(self.headers.get("content-length", "0"))
            release = json.loads(self.rfile.read(size))
            repo = "/".join(parts[2:4])
            host = self.headers.get("host", f"127.0.0.1:{self.server.server_port}")
            public_base = f"http://{host}"
            release = self.server.state.publish(repo, release, public_base)
            self.json_response(201, release)
        except (ValueError, OSError, json.JSONDecodeError) as error:
            self.json_response(400, {"error": str(error)})

    def do_GET(self):
        path = urlsplit(self.path).path
        if path.startswith("/__assets/"):
            self.serve_asset(unquote(path.removeprefix("/__assets/")))
            return
        # GitHub-compatible paths below /repos/{owner}/{repo}/releases...
        parts = path.strip("/").split("/")
        if len(parts) >= 4 and parts[0] == "repos":
            repo = "/".join(parts[1:3])
            suffix = parts[3:]
            local = self.server.state.releases.get(repo, {})
            if suffix == ["releases"] and local:
                # Preserve local newest-first ordering, then add non-shadowed upstream releases.
                upstream = self.fetch_upstream_json()
                if isinstance(upstream, list):
                    local_tags = set(local)
                    upstream = [r for r in upstream if r.get("tag_name") not in local_tags]
                else:
                    upstream = []
                self.json_response(200, list(local.values()) + upstream)
                return
            if suffix == ["releases", "latest"] and local:
                self.json_response(200, next(iter(local.values())))
                return
            if len(suffix) == 3 and suffix[:2] == ["releases", "tags"]:
                release = local.get(unquote(suffix[2]))
                if release:
                    self.json_response(200, release)
                    return
        self.relay()

    def serve_asset(self, name):
        if not name or Path(name).name != name:
            self.send_error(400, "invalid asset name")
            return
        path = self.server.state.asset_dir / name
        if not path.is_file():
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("content-type", mimetypes.guess_type(name)[0] or "application/octet-stream")
        self.send_header("content-length", str(path.stat().st_size))
        self.end_headers()
        with path.open("rb") as source:
            shutil.copyfileobj(source, self.wfile)

    def upstream_request(self):
        url = UPSTREAM + self.path
        headers = {"user-agent": "dstack-release-mock", "accept": "application/vnd.github+json"}
        auth = self.headers.get("authorization")
        if auth:
            headers["authorization"] = auth
        return urllib.request.Request(url, headers=headers)

    def fetch_upstream_json(self):
        try:
            with urllib.request.urlopen(self.upstream_request(), timeout=30) as response:
                return json.load(response)
        except (urllib.error.URLError, json.JSONDecodeError):
            return []

    def relay(self):
        try:
            with urllib.request.urlopen(self.upstream_request(), timeout=30) as response:
                body = response.read()
                self.send_response(response.status)
                self.send_header("content-type", response.headers.get("content-type", "application/json"))
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        except urllib.error.HTTPError as error:
            body = error.read()
            self.send_response(error.code)
            self.send_header("content-type", error.headers.get("content-type", "application/json"))
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except urllib.error.URLError as error:
            self.json_response(502, {"error": f"upstream request failed: {error}"})

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))


class Server(ThreadingHTTPServer):
    def __init__(self, address, state):
        super().__init__(address, Handler)
        self.state = state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--asset-dir", type=Path, default=Path("/tmp/dstack-release-mock-assets"))
    args = parser.parse_args()
    server = Server((args.listen, args.port), State(args.asset_dir))
    print(f"release API: http://{args.listen}:{args.port}/repos", flush=True)
    print(f"publish API: http://{args.listen}:{args.port}/__admin/repos/OWNER/REPO/releases", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
