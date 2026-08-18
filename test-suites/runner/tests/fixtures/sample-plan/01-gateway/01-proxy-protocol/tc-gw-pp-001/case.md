<a id="tc-gw-pp-001"></a>
# TC-GW-PP-001: Forward a Proxy v1 address

<a id="tc-gw-pp-001-objective"></a>
## Objective

Verify that a PP-enabled backend receives the declared source address.

<a id="tc-gw-pp-001-steps"></a>
## Steps

<a id="tc-gw-pp-001-step-01"></a>
### Step 1: Query policy

**Expected result:** port 8443 has `pp=true`.

<a id="tc-gw-pp-001-step-02"></a>
### Step 2: Send request

**Expected result:** the backend receives `198.51.100.27:45678`.
