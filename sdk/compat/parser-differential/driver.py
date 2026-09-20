# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

import json, os, socket, sys, warnings
warnings.simplefilter("ignore")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "python", "src"))
sock, case, method = sys.argv[1], sys.argv[2], sys.argv[3]

def select(case):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(sock)
    s.sendall(("POST /__case/%s HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n" % case).encode())
    s.recv(4096); s.close()

def t(f):
    try:
        v = f()
        return v.hex() if isinstance(v, (bytes, bytearray)) else str(v)
    except BaseException as e:
        return "<%s>" % type(e).__name__

select(case)
from dstack_sdk import DstackClientV1, DstackClientV0
c = DstackClientV0(sock) if method.startswith("v0") else DstackClientV1(sock)
try:
    if method == "GetKey":
        r = c.get_key("d", "secp256k1"); out = "key=%s chain=%d" % (r.key.hex()[:16], len(r.signature_chain))
    elif method == "Info":
        r = c.info(); out = "app_id=%s app_name=%r os_image_hash=%s" % (r.app_id.hex()[:16], r.app_name, r.os_image_hash.hex()[:16])
    elif method == "Attest":
        r = c.attest(b"\x01"*32); out = "attestation=%dB gpu=%d" % (len(r.attestation), len(r.boottime_gpu_evidence))
    elif method == "v0GetKey":
        r = c.get_key("d"); out = "key=%s chain=%d decode=%s" % (r.key[:16], len(r.signature_chain), t(r.decode_key))
    elif method == "v0Info":
        r = c.info(); out = "app_id=%s tcb=%s" % (r.app_id[:16], type(r.tcb_info).__name__)
    elif method == "v0TlsKey":
        r = c.get_tls_key(); out = "as32=%s fulllen=%s" % (t(lambda: r.as_uint8array(32)), t(lambda: len(r.as_uint8array())))
    print("OK|%s" % out)
except BaseException as e:
    print("ERR|%s: %s" % (type(e).__name__, str(e).replace("\n", " ")[:160]))
