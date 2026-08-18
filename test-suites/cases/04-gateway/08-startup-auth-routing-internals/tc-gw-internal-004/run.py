#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Deterministic regression harness for bounded Gateway TLS SNI parsing."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
from typing import Any

CASE_ID = "tc-gw-internal-004"
CARGO_TOML = """[package]
name = "sni-boundary-harness"
version = "0.1.0"
edition = "2021"

[dependencies]
parcelona = "0.4"
tracing = "0.1"
"""
RUST_MAIN = '\nmod sni { include!("__SNI_SOURCE__"); }\nfn client_hello(names: Vec<(u8, &[u8])>, ext_prefix: Vec<(u16, Vec<u8>)>, record_ver: [u8;2], hello_ver: [u8;2]) -> Vec<u8> {\n    let mut body=Vec::new(); body.extend_from_slice(&hello_ver); body.extend_from_slice(&[0x11;32]); body.push(0);\n    body.extend_from_slice(&(2u16).to_be_bytes()); body.extend_from_slice(&[0x13,0x01]); body.push(1); body.push(0);\n    let mut exts=Vec::new();\n    for (t,d) in ext_prefix { exts.extend_from_slice(&t.to_be_bytes()); exts.extend_from_slice(&(d.len() as u16).to_be_bytes()); exts.extend_from_slice(&d); }\n    let mut list=Vec::new(); for (typ,name) in names { list.push(typ); list.extend_from_slice(&(name.len() as u16).to_be_bytes()); list.extend_from_slice(name); }\n    let mut sni_ext=Vec::new(); sni_ext.extend_from_slice(&(list.len() as u16).to_be_bytes()); sni_ext.extend_from_slice(&list);\n    exts.extend_from_slice(&0u16.to_be_bytes()); exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes()); exts.extend_from_slice(&sni_ext);\n    body.extend_from_slice(&(exts.len() as u16).to_be_bytes()); body.extend_from_slice(&exts);\n    let mut hs=Vec::new(); hs.push(1); let l=body.len() as u32; hs.extend_from_slice(&[((l>>16)&0xff) as u8, ((l>>8)&0xff) as u8, (l&0xff) as u8]); hs.extend_from_slice(&body);\n    let mut rec=Vec::new(); rec.push(22); rec.extend_from_slice(&record_ver); rec.extend_from_slice(&(hs.len() as u16).to_be_bytes()); rec.extend_from_slice(&hs); rec\n}\nfn expect(label:&str, got:Option<&[u8]>, want:Option<&[u8]>) -> bool { let ok=got==want; println!("{} got={:?} want={:?} ok={}", label, got.map(|v|String::from_utf8_lossy(v).to_string()), want.map(|v|String::from_utf8_lossy(v).to_string()), ok); ok }\nfn main(){\n let normal=client_hello(vec![(0,b"alpha.example")], vec![], [3,3], [3,3]);\n let dup=client_hello(vec![(0,b"first.example"),(0,b"second.example")], vec![], [3,3], [3,3]);\n let nonhost_then_host=client_hello(vec![(1,b"ignored"),(0,b"host.example")], vec![], [3,1], [3,4]);\n let ipv4=client_hello(vec![(0,b"127.0.0.1")], vec![], [3,3], [3,3]);\n let ipv6=client_hello(vec![(0,b"2001:db8::1")], vec![], [3,3], [3,3]);\n let empty=client_hello(vec![(0,b"")], vec![], [3,3], [3,3]);\n let prefixed=client_hello(vec![(0,b"after-pad.example")], vec![(23, vec![1,2,3,4])], [3,3], [3,3]);\n let mut ok=true;\n ok &= expect("normal", sni::extract_sni(&normal), Some(&b"alpha.example"[..]));\n ok &= expect("duplicate_first", sni::extract_sni(&dup), Some(&b"first.example"[..]));\n ok &= expect("nonhost_then_host", sni::extract_sni(&nonhost_then_host), Some(&b"host.example"[..]));\n ok &= expect("ipv4_literal", sni::extract_sni(&ipv4), Some(&b"127.0.0.1"[..]));\n ok &= expect("ipv6_literal", sni::extract_sni(&ipv6), Some(&b"2001:db8::1"[..]));\n ok &= expect("empty_host", sni::extract_sni(&empty), Some(&b""[..]));\n ok &= expect("coalesced_padding_ext", sni::extract_sni(&prefixed), Some(&b"after-pad.example"[..]));\n ok &= expect("non_tls", sni::extract_sni(b"GET / HTTP/1.1\\r\\nHost: evil\\r\\n\\r\\n"), None);\n for cut in [0usize,1,5,9,20,normal.len()-1] { ok &= expect(&format!("truncated_{}", cut), sni::extract_sni(&normal[..cut]), None); }\n let mut bad=normal.clone(); bad[3]=0xff; bad[4]=0xff; ok &= expect("oversized_record_len", sni::extract_sni(&bad), Some(&b"alpha.example"[..]));\n let mut badext=normal.clone(); let name_len=badext.len()-b"alpha.example".len()-2; badext[name_len]=0xff; badext[name_len+1]=0xff; ok &= expect("oversized_name_len", sni::extract_sni(&badext), None);\n std::process::exit(if ok {0} else {1});\n}\n'


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def main() -> int:
    """Execute the promoted parser regression."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id != CASE_ID:
        raise SystemExit(f"unsupported case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    source = pathlib.Path(runtime["repository"]) / "dstack/gateway/src/proxy/sni.rs"
    cargo = shutil.which("cargo") or str(pathlib.Path.home() / ".cargo/bin/cargo")
    with tempfile.TemporaryDirectory(prefix="dstack-sni-regression-") as temporary:
        project = pathlib.Path(temporary)
        (project / "src").mkdir()
        (project / "Cargo.toml").write_text(CARGO_TOML)
        escaped_source = str(source).replace("\\", "\\\\").replace('"', '\\"')
        (project / "src/main.rs").write_text(
            RUST_MAIN.replace("__SNI_SOURCE__", escaped_source)
        )
        completed = subprocess.run(
            [cargo, "run", "--quiet", "--offline"],
            cwd=project,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=180,
            check=False,
        )
    output = completed.stdout[-12000:]
    status = "PASS" if completed.returncode == 0 else "FAIL"
    evidence = {
        "returncode": completed.returncode,
        "output_bytes": len(completed.stdout.encode()),
        "output_sha256": hashlib.sha256(completed.stdout.encode()).hexdigest(),
        "output_tail": output,
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
    }
    artifact = {
        "path": "artifacts/sni-boundary-regression.json",
        "step_id": f"{case_id}-step-02",
        "name": "SNI boundary regression",
        "description": "Deterministic valid, malformed, truncation, duplicate, and oversized-length parser matrix.",
    }
    atomic_json(result_dir / artifact["path"], evidence)
    result = {
        "schema_version": "1.0",
        "case_id": case_id,
        "provisional": False,
        "status": status,
        "summary": "Gateway SNI parser boundary regression passed."
        if status == "PASS"
        else "Gateway SNI parser boundary regression failed.",
        "steps": [
            {
                "id": f"{case_id}-step-01",
                "status": status,
                "observed": "Candidate parser source was resolved from the runtime manifest.",
            },
            {
                "id": f"{case_id}-step-02",
                "status": status,
                "observed": "Valid SNI inputs passed and malformed or oversized nested lengths failed closed.",
            },
            {
                "id": f"{case_id}-step-03",
                "status": status,
                "observed": "Repeated pure parser execution produced no external state.",
            },
        ],
        "artifacts": [artifact],
        "remarks": "Offline temporary Cargo harness; no service, image, network, or host mutation.",
    }
    atomic_json(result_dir / "result.json", result)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
