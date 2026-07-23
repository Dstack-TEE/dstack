# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Embedded live dashboard for dstack test runs."""

import http.server
import json
import threading
import urllib.parse
from typing import Any, Callable

HTML = r"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>dstack test</title><style>
:root{color-scheme:dark;font:14px system-ui;background:#0b1020;color:#dce5ff}body{margin:0}header{padding:16px 22px;background:#121a30}h1{margin:0;font-size:20px}.meta{color:#91a4cc}.grid{display:grid;grid-template-columns:360px 1fr;min-height:calc(100vh - 65px)}aside,main{padding:16px}aside{border-right:1px solid #273453}.case{display:block;width:100%;text-align:left;background:#151e35;color:inherit;border:1px solid #293858;border-radius:8px;padding:10px;margin:7px 0;cursor:pointer}.case:hover,.active{border-color:#6da7ff}.badge{float:right;border-radius:10px;padding:2px 7px;font-size:11px}.PASS{background:#126b47}.FAIL{background:#8b2733}.SKIPPED,.BLOCKED{background:#74551b}.RUNNING{background:#215a91}.PENDING{background:#39445d}.summary{display:flex;gap:6px;flex-wrap:wrap}.summary span{background:#1a2540;padding:5px 8px;border-radius:12px}button{color:inherit}pre{white-space:pre-wrap;word-break:break-word;background:#070b14;border:1px solid #273453;border-radius:8px;padding:14px;height:calc(100vh - 135px);overflow:auto}.toolbar{display:flex;gap:10px;align-items:center}@media(max-width:800px){.grid{grid-template-columns:1fr}}</style></head><body><header><h1 id="title">dstack test</h1><div class="meta" id="meta">Connecting…</div></header><div class="grid"><aside><div class="summary" id="summary"></div><div id="cases"></div></aside><main><div class="toolbar"><strong id="agent">Plan orchestrator</strong><button onclick="resetLog()">Reload history</button><label><input id="follow" type="checkbox" checked> follow</label></div><pre id="log"></pre></main></div><script>
let selected='orchestrator',offset=0;const log=document.querySelector('#log');const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function pick(id,label){selected=id;offset=0;log.textContent='';document.querySelector('#agent').textContent=label;pollLog()}function resetLog(){offset=0;log.textContent='';pollLog()}
async function pollState(){try{const s=await(await fetch('/api/state')).json();title.textContent=s.title;meta.textContent=`run ${s.run_id} · ${s.run_status}`;summary.innerHTML=Object.entries(s.counts).filter(x=>x[1]).map(x=>`<span>${esc(x[0])} ${x[1]}</span>`).join('');let h=`<button class="case" onclick="pick('orchestrator','Plan orchestrator')">Plan orchestrator<span class="badge ${s.orchestrator_status}">${s.orchestrator_status}</span></button>`;for(const c of s.cases)h+=`<button class="case" onclick="pick('case:${esc(c.id)}','${esc(c.id)}')">${esc(c.id)}<span class="badge ${c.status}">${c.status}</span><br><small>${esc(c.title)}</small></button>`;cases.innerHTML=h}catch(e){meta.textContent=e}}
async function pollLog(){try{const r=await(await fetch(`/api/log?agent=${encodeURIComponent(selected)}&offset=${offset}`)).json();if(r.reset){offset=0;log.textContent=''}if(r.text){log.textContent+=r.text;offset=r.next_offset;if(follow.checked)log.scrollTop=log.scrollHeight}}catch(e){}}
setInterval(pollState,1000);setInterval(pollLog,500);pollState();pollLog();</script></body></html>"""


class Dashboard:
    """Serve a read-only live run dashboard."""

    def __init__(
        self,
        state: Callable[[], dict[str, Any]],
        log: Callable[[str, int], dict[str, Any]],
        host: str,
        port: int,
    ):
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, _format: str, *_args: Any) -> None:
                pass

            def reply(self, value: Any, status: int = 200) -> None:
                data = json.dumps(value, ensure_ascii=False).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path == "/":
                    data = HTML.encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                elif parsed.path == "/api/state":
                    self.reply(state())
                elif parsed.path == "/api/log":
                    query = urllib.parse.parse_qs(parsed.query)
                    try:
                        self.reply(
                            log(
                                query.get("agent", [""])[0],
                                int(query.get("offset", ["0"])[0]),
                            )
                        )
                    except Exception as error:  # noqa: BLE001 - API boundary
                        self.reply({"error": str(error)}, 400)
                else:
                    self.send_error(404)

        self.server = http.server.ThreadingHTTPServer((host, port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def address(self) -> tuple[str, int]:
        host, port = self.server.server_address[:2]
        return str(host), int(port)

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
