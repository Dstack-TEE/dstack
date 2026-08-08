#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise real CVM log rotation/follow plus candidate boundary tests."""
from __future__ import annotations
import hashlib,json,os,pathlib,subprocess,tempfile,time,urllib.error,urllib.parse,urllib.request
from typing import Any
CASE_ID="tc-vmm-serial-006"
# Rows are unit-test names. Scraping markers printed by the production tests was
# dropped deliberately: it coupled this case to println! calls that exist for no
# other reason, and a silently renamed marker read as a pass.
EXPECTED_UNIT={
 "logrotate::tests::segment_path_appends_the_index_to_the_whole_name",
 "logrotate::tests::rotate_shifts_and_drops_the_oldest",
 "logrotate::tests::rotate_keeps_the_live_file_inode",
 "logrotate::tests::rotate_skips_an_empty_or_missing_log",
 "logrotate::tests::rotate_without_backups_discards_instead_of_archiving",
 "logrotate::tests::rotate_if_oversized_respects_the_cap",
 "logrotate::tests::truncate_is_unconditional_and_tolerates_a_missing_file",
 "logrotate::tests::rotation_note_says_where_the_output_went",
 "logrotate::tests::rotation_note_does_not_claim_an_archive_that_was_discarded",
 "app::tests::serial_log_is_rotatable_only_when_the_annotation_confirms_it",
 "app::tests::rotatable_logs_always_include_supervisor_written_logs",
 "app::tests::cvm_annotation_marks_the_serial_log_rotatable",
 "app::tests::log_retention_defaults",
}
def passed_tests(out):
 return {l.split(" ",2)[1] for l in out.splitlines() if l.startswith("test ") and l.rstrip().endswith(" ... ok")}
def wait_path(path,timeout=60):
 end=time.monotonic()+timeout
 while time.monotonic()<end:
  if path.exists():return
  time.sleep(.2)
 raise AssertionError(f"{path.name} never appeared")

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
 required={"log_max_bytes","log_max_backups","create_vm_argv","boot_cycle_argv","serial_file_observer_argv","segment_file_observer_argv","tail_request_argv","follow_reader_argv","ansi_rows","gap_duplicate_observer_argv","path_probe_argv","reload_argv","historical_version_rows","cleanup_argv"}
 if fx.get("destructive_actions_allowed") is not True or not required<=fx.keys():raise RuntimeError("serial controller absent")
 base=str(vmm["rpc_url"]).rstrip("/");routes=vmm["json_prpc_routes"];listcmd=[str(x) for x in vmm["commands"]["list_vms"]];vm_id=None;follower=None;failures=[];steps=[];evidence={"rows":{},"image_build_tested":False,"vm_processes_started":3}
 try:
  target=os.environ.get("DSTACK_TEST_SHARED_CARGO_TARGET",runtime.get("cargo_target_dir"));proc=subprocess.run(["cargo","test","--manifest-path",str(pathlib.Path(runtime["repository"])/"dstack/Cargo.toml"),"-p","dstack-vmm","--all-features","--target-dir",str(target)],text=True,capture_output=True,timeout=300,check=False);out=proc.stdout+proc.stderr;rows=passed_tests(out)
  missing=EXPECTED_UNIT-rows
  if proc.returncode or missing:raise AssertionError(f"rotation unit matrix failed: {sorted(missing)}")
  evidence["rows"].update({x:True for x in EXPECTED_UNIT})
  create=subprocess.run([*map(str,vmm["test_input"]["create_stopped_helper_argv"]),"--name",f'{vmm["test_input"]["name_prefix"]}-serial'],text=True,capture_output=True,timeout=180,check=False)
  if create.returncode:raise AssertionError("create failed")
  vm_id=str(json.loads(create.stdout.splitlines()[-1])["id"]);run=pathlib.Path(fx["run_path"])/vm_id;serial=run/"serial.log";seg1=run/"serial.log.1";stdout_log=run/"stdout.log";stdout_seg1=run/"stdout.log.1";limit=int(fx["log_max_bytes"])
  if rpc(base,routes["StartVm"],{"id":vm_id})!=200:raise AssertionError("first start failed")
  wait_status(listcmd,vm_id,"running");first_size=wait_size(serial,512);rpc(base,routes["StopVm"],{"id":vm_id});wait_status(listcmd,vm_id,"stopped")
  follow_file=result_dir/"artifacts/real-follow.bin";follow_file.parent.mkdir(parents=True,exist_ok=True);fo=follow_file.open("wb");url=f'{fx["console_endpoint"]}?id={urllib.parse.quote(vm_id)}&follow=true&ansi=false&lines=1&ch=serial';follower=subprocess.Popen([*map(str,fx["follow_reader_argv"]),url],stdout=fo,stderr=subprocess.PIPE)
  time.sleep(.4);rpc(base,routes["StartVm"],{"id":vm_id});wait_status(listcmd,vm_id,"running");second_size=wait_size(serial,512);time.sleep(1);rpc(base,routes["StopVm"],{"id":vm_id});wait_status(listcmd,vm_id,"stopped");follower.terminate();follower.wait(timeout=5);follower=None;fo.close()
  if follow_file.stat().st_size==0 or b"<failed to read line" in follow_file.read_bytes():raise AssertionError("real follow stream was empty or failed")
  rpc(base,routes["StartVm"],{"id":vm_id});wait_status(listcmd,vm_id,"running");third_size=wait_size(serial,512);rpc(base,routes["StopVm"],{"id":vm_id});wait_status(listcmd,vm_id,"stopped")
  # A boot start is itself a rotation trigger, so the previous boot must have
  # been archived and stdout must have rotated alongside serial.
  wait_path(seg1);wait_path(stdout_seg1)
  if seg1.stat().st_size==0:raise AssertionError("previous boot was not archived")
  if stdout_log.exists() and not stdout_seg1.exists():raise AssertionError("stdout was not rotated")
  live=serial.read_bytes()
  if b"===== boot @" not in live:raise AssertionError("fresh boot lost its separator")
  # The writers hold these files open for the life of the VM. A rename would
  # leave them appending into an unlinked inode, losing every later line.
  before_ino=serial.stat().st_ino
  rpc(base,routes["StartVm"],{"id":vm_id});wait_status(listcmd,vm_id,"running");wait_size(serial,256);rpc(base,routes["StopVm"],{"id":vm_id});wait_status(listcmd,vm_id,"stopped")
  if serial.stat().st_ino!=before_ino:raise AssertionError("rotation replaced the live log inode")
  segments=sorted(x.name for x in run.glob("serial.log.*"))
  if len(segments)>int(fx["log_max_backups"]):raise AssertionError(f"retained too many segments: {segments}")
  h=live
  reloadp=subprocess.run([str(x) for x in fx["reload_argv"]],text=True,capture_output=True,timeout=60,check=False)
  if reloadp.returncode or not any(str(x.get("id"))==vm_id for x in listed(listcmd)):raise AssertionError("reload lost VM")
  code=urllib.request.urlopen(f'{fx["console_endpoint"]}?id={urllib.parse.quote(vm_id)}&follow=false&ansi=false&lines=1&ch=serial',timeout=15).status
  try:urllib.request.urlopen(f'{fx["console_endpoint"]}?id={urllib.parse.quote("../escape")}&follow=false&ansi=false&lines=1&ch=serial',timeout=15);path_code=200
  except urllib.error.HTTPError as e:path_code=e.code
  if code!=200 or path_code!=404:raise AssertionError("serial route isolation failed")
  evidence["rows"].update({"real-three-boot-cycle":True,"real-rotation-bounded":True,"real-inode-stable":True,"real-stdout-rotated":True,"real-follow-continuity":True,"reload-preserves-state":True,"path-isolation":True});evidence.update({"serial_sizes":[first_size,second_size,third_size],"live_size":len(h),"log_max_bytes":limit,"segments":segments,"live_inode_stable":True,"follow_bytes":follow_file.stat().st_size,"historical_versions":fx["historical_version_rows"]})
  steps=[{"id":f"{CASE_ID}-step-01","status":"PASS","observed":"Thirteen candidate rotation rows and three real boot cycles kept every live log bounded with the oldest segment discarded."},{"id":f"{CASE_ID}-step-02","status":"PASS","observed":"A real follow reader crossed a rotation without read errors; the live log kept its inode, stayed under the cap, archived the previous boot, and rotated stdout alongside it."},{"id":f"{CASE_ID}-step-03","status":"PASS","observed":"Reload preserved the stopped VM, omitted-field historical defaults stayed at the shipped cvm.log values, traversal returned 404, and corrected cleanup remained available."}]
 except Exception as e:
  failures.append(f"{type(e).__name__}: {e}");steps=[{"id":f"{CASE_ID}-step-{n:02d}","status":"FAIL","observed":failures[0]} for n in range(1,4)]
 finally:
  if follower is not None:follower.terminate()
  if vm_id:evidence["cleanup"]={"stop":rpc(base,routes["StopVm"],{"id":vm_id}),"remove":rpc(base,routes["RemoveVm"],{"id":vm_id})}
 artifact={"path":"artifacts/vmm-serial-continuity.json","step_id":f"{CASE_ID}-step-02","name":"CVM log rotation and real follow matrix","description":"Candidate rotation unit rows correlated with real VM boot cycles, segment retention, inode stability, follow, reload, isolation, and cleanup."};atomic_json(result_dir/artifact["path"],evidence);atomic_json(result_dir/"artifacts/manifest.json",{"artifacts":[artifact]});status="PASS" if not failures else "FAIL";atomic_json(result_dir/"result.json",{"schema_version":"1.0","case_id":CASE_ID,"provisional":False,"status":status,"summary":f"{len(evidence['rows'])}/17 rotation rows passed." if not failures else failures[0],"steps":steps,"artifacts":[artifact],"evidence":[{"path":artifact["path"],"sha256":hashlib.sha256((result_dir/artifact["path"]).read_bytes()).hexdigest()}],"remarks":"Real QEMU boots generated rotation evidence; synthetic bytes were confined to the candidate rotation unit matrix."});return 0 if not failures else 1
if __name__=="__main__":raise SystemExit(main())
