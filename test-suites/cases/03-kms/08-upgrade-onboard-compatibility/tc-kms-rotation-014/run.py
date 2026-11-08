#!/usr/bin/env python3
"""Run the complete Foundry contract rotation suite."""
import hashlib, json, os, pathlib, subprocess
CASE="tc-kms-rotation-014"
def main():
 if os.environ.get("DSTACK_TEST_CASE_ID") != CASE: raise SystemExit("unsupported case")
 runtime=json.loads(pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()); repo=pathlib.Path(runtime["repository"])
 command=["forge","test","--offline","--ffi","--match-path","test/DstackKms.t.sol","--match-path","test/DstackApp.t.sol","--match-path","test/UpgradesWithPlugin.t.sol"]
 result=subprocess.run(command,cwd=repo/"dstack/kms/auth-eth",text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=600)
 out=result.stdout; passed=next((int(x.split()[0]) for x in out.splitlines() if "tests passed" in x),0)
 status="PASS" if result.returncode==0 and passed>0 else "FAIL"; rd=pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"]); (rd/"artifacts").mkdir(parents=True,exist_ok=True)
 (rd/"artifacts/contract-rotation-matrix.json").write_text(json.dumps({"status":status,"passed":passed,"output_sha256":hashlib.sha256(out.encode()).hexdigest()},indent=2)+"\n")
 (rd/"result.json").write_text(json.dumps({"schema_version":"1.0","case_id":CASE,"provisional":False,"status":status,"summary":f"{passed} contract rotation tests passed"},indent=2)+"\n"); return 0 if status=="PASS" else 1
if __name__=="__main__": raise SystemExit(main())
