#!/usr/bin/env python3
"""Run all local epoch authorization backend suites."""
import json, os, pathlib, subprocess
CASE="tc-kms-rotation-015"
def main():
 if os.environ.get("DSTACK_TEST_CASE_ID") != CASE: raise SystemExit("unsupported case")
 repo=pathlib.Path(json.loads(pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())["repository"]); rows=[]
 for path in ["dstack/kms/auth-simple","dstack/kms/auth-mock","dstack/kms/auth-eth-bun","dstack/kms/auth-eth"]:
  cmd=["bun","run","test:run"] if (repo/path/"package.json").read_text().find('"test:run"')>=0 else ["npm","test","--","--runInBand"]
  r=subprocess.run(cmd,cwd=repo/path,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=300); rows.append({"path":path,"returncode":r.returncode})
 status="PASS" if all(x["returncode"]==0 for x in rows) else "FAIL"; rd=pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"]); (rd/"artifacts").mkdir(parents=True,exist_ok=True); (rd/"artifacts/backend-rotation-matrix.json").write_text(json.dumps({"status":status,"rows":rows},indent=2)+"\n"); (rd/"result.json").write_text(json.dumps({"schema_version":"1.0","case_id":CASE,"provisional":False,"status":status,"summary":"all epoch authorization backend suites passed"},indent=2)+"\n"); return 0 if status=="PASS" else 1
if __name__=="__main__": raise SystemExit(main())
