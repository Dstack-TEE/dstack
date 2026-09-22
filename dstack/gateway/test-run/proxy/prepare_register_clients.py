#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Create disposable AppInfo client certificates for register_load.py.

Requires openssl and Python msgpack. DIR must be an isolated test certificate
folder containing cert.pem and key.pem for its disposable CA. Never use a
production CA. Existing client files are not overwritten. No key is printed.
"""
import argparse
from pathlib import Path
import subprocess

import msgpack


def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    certs = args.directory
    for i in range(64):
        for suffix in ("pem", "key", "csr", "ext"):
            if (certs / f"client{i}.{suffix}").exists():
                parser.error("client files already exist; use a fresh test directory")
    for i in range(64):
        app = {k: b"" for k in (
            "app_id", "compose_hash", "instance_id", "device_id", "os_image_hash", "key_provider_info")}
        app.update(app_id=b"benchmark", instance_id=i.to_bytes(4, "big"),
                   mr_system=bytes(32), mr_aggregated=bytes(32))
        packed = msgpack.packb(app, use_bin_type=True)
        size = len(packed)
        length = bytes([size]) if size < 128 else bytes([0x82]) + size.to_bytes(2, "big")
        (certs / f"client{i}.ext").write_text(
            "[v3_ext]\nbasicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n"
            "1.3.6.1.4.1.62397.1.9=DER:" + (b"\x04" + length + packed).hex(":") + "\n")
        run("openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-nodes", "-keyout", str(certs / f"client{i}.key"),
            "-out", str(certs / f"client{i}.csr"), "-subj", f"/CN=client{i}")
        run("openssl", "x509", "-req", "-in", str(certs / f"client{i}.csr"),
            "-CA", str(certs / "cert.pem"), "-CAkey", str(certs / "key.pem"),
            "-set_serial", str(i+100), "-days", "2", "-out", str(certs / f"client{i}.pem"),
            "-extfile", str(certs / f"client{i}.ext"), "-extensions", "v3_ext")
    print("Prepared 64 disposable AppInfo client certificates.")


if __name__ == "__main__":
    main()
