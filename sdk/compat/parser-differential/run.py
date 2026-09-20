#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

import json, os, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SDK = os.path.abspath(os.path.join(HERE, "..", ".."))
SOCK = os.path.join(tempfile.mkdtemp(prefix="pdiff-"), "agent.sock")
CASES = json.load(open(os.path.join(HERE, "cases.json")))

srv = subprocess.Popen([sys.executable, os.path.join(HERE, "server.py"), SOCK, os.path.join(HERE, "cases.json")],
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
assert srv.stdout.readline().strip() == "READY"

PYTHON = os.environ.get("PDIFF_PYTHON", os.path.join(SDK, "python", ".venv", "bin", "python"))

RUNNERS = {
    "rust":   lambda c, m: [os.path.join(HERE, "rustdriver/target/debug/pdiff-rust"), SOCK, c, m],
    "python": lambda c, m: [PYTHON, os.path.join(HERE, "driver.py"), SOCK, c, m],
    "go":     lambda c, m: [os.path.join(HERE, "godriver/pdiff-go"), SOCK, c, m],
    "js":     lambda c, m: ["node", os.path.join(HERE, "driver.js"), SOCK, c, m],
}

results = {}
for name in sorted(CASES):
    method = CASES[name]["method"]
    row = {}
    for lang, mk in RUNNERS.items():
        try:
            p = subprocess.run(mk(name, method), capture_output=True, text=True, timeout=90)
            line = (p.stdout.strip().splitlines() or [""])[-1]
            if p.returncode != 0:
                tail = (p.stderr.strip().splitlines() or [""])
                sig = ""
                for l in tail:
                    if "panic" in l.lower() or "Traceback" in l or "Error" in l:
                        sig = l.strip(); break
                if not sig and tail: sig = tail[-1].strip()
                line = f"CRASH(rc={p.returncode})|{sig[:150]}"
        except subprocess.TimeoutExpired:
            line = "TIMEOUT|"
        row[lang] = line or "EMPTY|"
    results[name] = row
    print(f"--- {name} [{method}]")
    for lang in RUNNERS:
        print(f"    {lang:7s} {row[lang]}")

json.dump(results, open(os.path.join(HERE, "results.json"), "w"), indent=1)
srv.kill()
