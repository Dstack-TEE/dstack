# SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
"""Monitor certificate transparency logs for a given domain."""

import argparse
import sys
import time

import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

BASE_URL = "https://crt.sh"


class PoisonedLog(Exception):
    """Indicate a poisoned certificate transparency log entry."""

    pass


class Monitor:
    """Monitor certificate transparency logs for a domain."""

    def __init__(self, domain: str):
        """Initialize the monitor with a validated domain."""
        if not self.validate_domain(domain):
            raise ValueError("Invalid domain name")
        self.domain = domain
        self.last_checked = None

    def get_logs(self, count: int = 100):
        """Fetch recent certificate transparency log entries."""
        url = f"{BASE_URL}/?q={self.domain}&output=json&limit={count}"
        response = requests.get(url)
        return response.json()

    def check_one_log(self, log: object):
        """Fetch and inspect a single certificate log entry."""
        log_id = log["id"]
        cert_url = f"{BASE_URL}/?d={log_id}"
        cert_data = requests.get(cert_url).text
        # Extract PEM-encoded certificate
        import re

        pem_match = re.search(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            cert_data,
            re.DOTALL,
        )
        if pem_match:
            pem_cert = pem_match.group(0)

            # Parse PEM certificate
            cert = x509.load_pem_x509_certificate(pem_cert.encode(), default_backend())
            # Extract the public key
            public_key = cert.public_key()
            pem_public_key = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            print("Public Key:")
            print(pem_public_key.hex())
            # Extract and print the issuer
            print("Issuer:")
            for attr in cert.issuer:
                oid = attr.oid
                if oid._name is not None:
                    name = oid._name
                    print(f"  {name}: {attr.value}")
                else:
                    print(f"  {oid.dotted_string}: {attr.value}")
        else:
            print("No valid certificate found in the response.")

    def check_new_logs(self):
        """Check for new log entries since the last check."""
        logs = self.get_logs(count=10000)
        print("num logs", len(logs))
        for log in logs:
            print(f"log id={log['id']}")
            if log["id"] <= (self.last_checked or 0):
                break
            self.check_one_log(log)
            print("next")
        if len(logs) > 0:
            self.last_checked = logs[0]["id"]

    def run(self):
        """Run the monitor loop indefinitely."""
        print(f"Monitoring {self.domain}...")
        while True:
            try:
                self.check_new_logs()
            except PoisonedLog as err:
                print(err, file=sys.stderr)
                return
            except Exception as err:
                print(err, file=sys.stderr)
            time.sleep(60)  # Sleep for 1 minute (60 seconds)

    @staticmethod
    def validate_domain(domain: str):
        """Validate that the given string is a well-formed DNS domain name."""
        import re

        # Regular expression for validating domain names
        domain_regex = re.compile(
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        )

        if not domain_regex.match(domain):
            raise ValueError("Invalid domain name")

        return True


def main():
    """Parse arguments and start the certificate transparency monitor."""
    parser = argparse.ArgumentParser(
        description="Monitor certificate transparency logs"
    )
    parser.add_argument("-d", "--domain", help="The domain to monitor")
    args = parser.parse_args()
    monitor = Monitor(args.domain)
    monitor.run()
