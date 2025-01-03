#!/usr/bin/env python3
import os
import sys
import json
import enum
import logging
import argparse
import requests
from typing import Optional, Protocol
from pathlib import Path
from http.server import HTTPServer, SimpleHTTPRequestHandler
from http import HTTPStatus
import urllib.parse
from jinja2 import Environment, FileSystemLoader
from datetime import datetime, timedelta
from cert_generator import generate_all_keys

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class KMSState(enum.Enum):
    """Possible states of the KMS system"""
    NEEDS_SETUP = "needs_setup"
    READY = "ready"

class KMSService(Protocol):
    """Protocol for KMS service implementation"""
    def start(self, keys: dict) -> None:
        """Start the KMS service with the provided keys"""
        ...

class HTTPClient(Protocol):
    """Protocol for HTTP client implementation"""
    def post(self, url: str, json: dict, timeout: int) -> requests.Response:
        """Make a POST request"""
        ...

class DefaultKMSService:
    """Default implementation of KMS service"""
    def start(self, keys: dict) -> None:
        logger.info("Starting KMS service...")
        # TODO: Implement actual KMS service startup
        pass

class RequestsHTTPClient:
    """Default HTTP client implementation using requests"""
    def post(self, url: str, json: dict, timeout: int) -> requests.Response:
        return requests.post(url, json=json, timeout=timeout)

class KMSManager:
    """Manages KMS lifecycle and state"""
    def __init__(
        self,
        keys_path: Path,
        kms_service: Optional[KMSService] = None,
        http_client: Optional[HTTPClient] = None
    ):
        self.keys_path = keys_path
        self.kms_service = kms_service or DefaultKMSService()
        self.http_client = http_client or RequestsHTTPClient()

    def check_state(self) -> KMSState:
        """Check current state of KMS"""
        if self.keys_path.exists():
            return KMSState.READY
        return KMSState.NEEDS_SETUP

    def _save_keys(self, keys: dict) -> None:
        """Save keys to file"""
        with open(self.keys_path, 'w') as f:
            json.dump(keys, f)

    def _load_keys(self) -> dict:
        """Load keys from file"""
        with open(self.keys_path) as f:
            return json.load(f)

    def bootstrap(self, domain: str, org_name: str) -> None:
        """Bootstrap a new KMS instance"""
        logger.info(f"Bootstrapping new KMS instance for domain {domain}")
        keys = generate_all_keys(domain, org_name)
        self._save_keys(keys)
        self.kms_service.start(keys)

    def onboard(self, source_url: str, domain: str, org_name: str) -> None:
        """Onboard from existing KMS"""
        logger.info(f"Onboarding from {source_url} for domain {domain}")
        try:
            response = self.http_client.post(
                f"{source_url}/onboard",
                json={"domain": domain, "org_name": org_name},
                timeout=30
            )
            response.raise_for_status()
            keys = response.json()
            self._save_keys(keys)
            self.kms_service.start(keys)
        except Exception as e:
            logger.error(f"Failed to onboard: {str(e)}")
            raise

# Initialize Jinja2 environment
templates = Environment(
    loader=FileSystemLoader(str(Path(__file__).parent / "templates"))
)

# Initialize KMS manager
kms_manager = KMSManager(keys_path=Path("/var/lib/dstack/kms/keys.json"))

class KMSHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            template = templates.get_template("index.html")
            self.wfile.write(template.render().encode())
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        params = urllib.parse.parse_qs(post_data)

        try:
            if self.path == "/bootstrap":
                domain = params.get('domain', [''])[0]
                org_name = params.get('org_name', [''])[0]
                kms_manager.bootstrap(domain, org_name)
            elif self.path == "/onboard":
                source_url = params.get('source_url', [''])[0]
                domain = params.get('domain', [''])[0]
                org_name = params.get('org_name', [''])[0]
                kms_manager.onboard(source_url, domain, org_name)
            else:
                self.send_error(HTTPStatus.NOT_FOUND)
                return

            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", "/")
            self.end_headers()
        except Exception as e:
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            template = templates.get_template("index.html")
            error_message = f"Operation failed: {str(e)}"
            self.wfile.write(template.render(error=error_message).encode())

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="DStack KMS Service")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8080, help="Port to bind to")
    parser.add_argument(
        "--keys-path",
        type=Path,
        default="/var/lib/dstack/kms/keys.json",
        help="Path to keys file"
    )
    args = parser.parse_args()

    # Update global KMS manager
    global kms_manager
    kms_manager = KMSManager(keys_path=args.keys_path)

    # Check current state
    state = kms_manager.check_state()
    
    if state == KMSState.READY:
        # Start KMS service if keys exist
        keys = kms_manager._load_keys()
        kms_manager.kms_service.start(keys)
    else:
        # Start setup web server if no keys
        logger.info("No existing keys found, starting setup web server...")
        server = HTTPServer((args.host, args.port), KMSHandler)
        logger.info(f"Server started at http://{args.host}:{args.port}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            logger.info("Server stopped")

if __name__ == "__main__":
    main()
