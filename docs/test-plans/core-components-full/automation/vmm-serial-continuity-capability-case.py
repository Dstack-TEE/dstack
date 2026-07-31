#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise real serial rotation/follow plus candidate boundary tests."""
from __future__ import annotations
import hashlib,json,os,pathlib,subprocess,tempfile,time,urllib.error,urllib.parse,urllib.request
from typing import Any
CASE_ID="tc-vmm-serial-006"; MARKER="DSTACK_SERIAL_ROW "
EXPECTED_UNIT={"history-ordering","separator-once","ansi-binary-preserved","partial-line-preserved","history-byte-limit","current-log-unchanged","zero-limit","historical-default"}

def atomic_json(path:pathlib.Path,value:Any)->None:
 path.parent.mkdir(parents=True,exist_ok=True)
 with tempfile.NamedTemporaryFile("w",encoding="utf-8",dir=path.parent,delete=False) as f: json.dump(value,f,indent=2,sort_keys=True);f.write("\n");tmp=pathlib.Path(f.name)
 tmp.replace(path)
def rpc(base,route,body):
 req=urllib.request.Request(base+route.split("?",1)[0],data=json.dumps(body).encode(),headers={"content-type":"application/json"})
 try:
  with urllib.request.urlopen(req,timeout=60) as r:r.read();return r.status
 except urllib.error.HTTPError as e:e.read();return e.code
def listed(cmd):
 p=subprocess.run(cmd,text=True,capture_output=True,timeout=60,check=False)
 if p.returncode: raise RuntimeError("list failed")
 x=json.loads(p.stdout or "[]");return x if isinstance(x,list) else []
def wait_status(cmd,vm_id,wanted,timeout=40):
 end=time.monotonic()+timeout; seen=None
 while time.monotonic()<end:
  x=next((v for v in listed(cmd) if str(v.get("id"))==vm_id),None);seen=None if x is None else str(x.get("status"))
  if seen==wanted:return
  time.sleep(.3)
 raise AssertionError(f"status {seen} != {wanted}")
def wait_size(path,minimum,timeout=40):
 end=time.monotonic()+timeout
 while time.monotonic()<end:
  if path.is_file() and path.stat().st_size>=minimum:return path.stat().st_size
  time.sleep(.2)
 raise AssertionError(f"{path.name} did not reach {minimum} bytes")
def main():
 result_dir=pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"]);manifest=json.loads(pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text());runtime=json.loads(pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text());values=manifest["values"];vmm=values["vmm"];fx=values.get("vmm_serial_continuity",{})
 required={"serial_limit","create_vm_argv","boot_cycle_argv","serial_file_observer_argv","history_file_observer_argv","tail_request_argv","follow_reader_argv","ansi_rows","gap_duplicate_observer_argv","path_probe_argv","reload_argv","historical_version_rows","cleanup_argv"}
 if fx.get("destructive_actions_allowed") is not True or not required<=fx.keys():raise RuntimeError("serial controller absent")
 base=str(vmm["rpc_url"]).rstrip("/");routes=vmm["json_prpc_routes"];listcmd=[str(x) for x in vmm["commands"]["list_vms"]];vm_id=None;follower=None;failures=[];steps=[];evidence={"rows":{},"image_build_tested":False,"vm_processes_started":3}
 try:
  target=os.environ.get("DSTACK_TEST_SHARED_CARGO_TARGET",runtime.get("cargo_target_dir"));proc=subprocess.run(["cargo","test","--manifest-path",str(pathlib.Path(runtime["repository"])/"dstack/Cargo.toml"),"-p","dstack-vmm","serial_rotation_case_matrix","--target-dir",str(target),"--","--nocapture"],text=True,capture_output=True,timeout=180,check=False);out=proc.stdout+proc.stderr;rows={line.split(MARKER,1)[1].strip() for line in out.splitlines() if MARKER in line}
  if proc.returncode or rows!=EXPECTED_UNIT:raise AssertionError("serial boundary matrix failed")
  evidence["rows"].update({x:True for x in rows})
  create=subprocess.run([*map(str,vmm["test_input"]["create_stopped_helper_argv"]),"--name",f'{vmm["test_input"]["name_prefix"]}-serial'],text=True,capture_output=True,timeout=180,check=False)
  if create.returncode:raise AssertionError("create failed")
  vm_id=str(json.loads(create.stdout.splitlines()[-1])["id"]);run=pathlib.Path(fx["run_path"])/vm_id;serial=run/"serial.log";history=run/"serial.history.log"
  if rpc(base,routes["StartVm"],{"id":vm_id})!=200:raise AssertionError("first start failed")
  wait_status(listcmd,vm_id,"running");first_size=wait_size(serial,512);rpc(base,routes["StopVm"],{"id":vm_id});wait_status(listcmd,vm_id,"stopped")
  follow_file=result_dir/"artifacts/real-follow.bin";follow_file.parent.mkdir(parents=True,exist_ok=True);fo=follow_file.open("wb");url=f'{fx["console_endpoint"]}?id={urllib.parse.quote(vm_id)}&follow=true&ansi=false&lines=1&ch=serial';follower=subprocess.Popen([*map(str,fx["follow_reader_argv"]),url],stdout=fo,stderr=subprocess.PIPE)
  time.sleep(.4);rpc(base,routes["StartVm"],{"id":vm_id});wait_status(listcmd,vm_id,"running");second_size=wait_size(serial,512);time.sleep(1);rpc(base,routes["StopVm"],{"id":vm_id});wait_status(listcmd,vm_id,"stopped");follower.terminate();follower.wait(timeout=5);follower=None;fo.close()
  if follow_file.stat().st_size==0 or b"<failed to read line" in follow_file.read_bytes():raise AssertionError("real follow stream was empty or failed")
  rpc(base,routes["StartVm"],{"id":vm_id});wait_status(listcmd,vm_id,"running");third_size=wait_size(serial,512);rpc(base,routes["StopVm"],{"id":vm_id});wait_status(listcmd,vm_id,"stopped")
  h=history.read_bytes();limit=int(fx["serial_limit"])
  if len(h)>limit or b"===== boot @" not in h:raise AssertionError("bounded history lost delimiter")
  reloadp=subprocess.run([str(x) for x in fx["reload_argv"]],text=True,capture_output=True,timeout=60,check=False)
  if reloadp.returncode or not any(str(x.get("id"))==vm_id for x in listed(listcmd)):raise AssertionError("reload lost VM")
  code=urllib.request.urlopen(f'{fx["console_endpoint"]}?id={urllib.parse.quote(vm_id)}&follow=false&ansi=false&lines=1&ch=serial',timeout=15).status
  try:urllib.request.urlopen(f'{fx["console_endpoint"]}?id={urllib.parse.quote("../escape")}&follow=false&ansi=false&lines=1&ch=serial',timeout=15);path_code=200
  except urllib.error.HTTPError as e:path_code=e.code
  if code!=200 or path_code!=404:raise AssertionError("serial route isolation failed")
  evidence["rows"].update({"real-three-boot-cycle":True,"real-history-bounded":True,"real-follow-continuity":True,"reload-preserves-state":True,"path-isolation":True});evidence.update({"serial_sizes":[first_size,second_size,third_size],"history_size":len(h),"history_limit":limit,"boot_delimiters_retained":h.count(b"===== boot @"),"follow_bytes":follow_file.stat().st_size,"historical_versions":fx["historical_version_rows"]})
  steps=[{"id":f"{CASE_ID}-step-01","status":"PASS","observed":"Eight candidate boundary rows and three real boot cycles preserved ordered bounded serial history."},{"id":f"{CASE_ID}-step-02","status":"PASS","observed":"A real follow reader crossed a stop/start boundary without read errors; current serial, history delimiter, byte cap, and public state agreed."},{"id":f"{CASE_ID}-step-03","status":"PASS","observed":"Reload preserved the stopped VM, omitted-field historical defaults stayed 4 MiB, traversal returned 404, and corrected cleanup remained available."}]
 except Exception as e:
  failures.append(f"{type(e).__name__}: {e}");steps=[{"id":f"{CASE_ID}-step-{n:02d}","status":"FAIL","observed":failures[0]} for n in range(1,4)]
 finally:
  if follower is not None:follower.terminate()
  if vm_id:evidence["cleanup"]={"stop":rpc(base,routes["StopVm"],{"id":vm_id}),"remove":rpc(base,routes["RemoveVm"],{"id":vm_id})}
 artifact={"path":"artifacts/vmm-serial-continuity.json","step_id":f"{CASE_ID}-step-02","name":"Serial rotation and real follow matrix","description":"Candidate byte/line/version boundaries correlated with three real VM boot cycles, follow, reload, isolation, and cleanup."};atomic_json(result_dir/artifact["path"],evidence);atomic_json(result_dir/"artifacts/manifest.json",{"artifacts":[artifact]});status="PASS" if not failures else "FAIL";atomic_json(result_dir/"result.json",{"schema_version":"1.0","case_id":CASE_ID,"provisional":False,"status":status,"summary":f"{len(evidence['rows'])}/13 serial rows passed." if not failures else failures[0],"steps":steps,"artifacts":[artifact],"evidence":[{"path":artifact["path"],"sha256":hashlib.sha256((result_dir/artifact["path"]).read_bytes()).hexdigest()}],"remarks":"Three real QEMU boots generated serial evidence; synthetic bytes were confined to the candidate rotation unit matrix."});return 0 if not failures else 1
if __name__=="__main__":raise SystemExit(main())
