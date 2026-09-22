# RegisterCvm interference benchmark

## Purpose and limitations

`register_load.py` measures the effect of registration floods on independent
`Info` requests and new TLS-terminated proxy connections. It uses the real
mTLS `RegisterCvm` route, not the debug API. It checks successful registration
responses, verifies each 1 KiB proxy response, and can verify that the kernel's
WireGuard peer set converges to every client's last acknowledged key.

This is a single-node, loopback interference test, not CVM tunnel throughput,
remote authorization latency, multi-node synchronization, or an Internet DDoS
capacity estimate. Each registration client is closed-loop (one outstanding
request). Each probe is sequential and capped at 50 requests/s; a blocked probe
cannot submit the next request. Interpret latency together with probe counts
and errors, rather than as an open-loop tail-latency guarantee.

## Reproduction

1. Build both versions with the same Rust toolchain and `cargo build --release
   -p dstack-gateway`. Keep separate copies of the resulting binaries. Create
   comparison worktrees under `original_project_dir.worktrees/`. The reference
   for this change is commit `548ad0dad2`, including its synchronous apply and
   dirty-loop implementation, not the earlier parent revision.
2. Follow the [simulator setup guide](https://gist.github.com/kvinwang/ec5697721bef09220d00909b2bd737c9).
   The Cargo package for the `dstack-simulator` executable is
   `dstack-guest-agent-simulator`. Use a disposable network namespace and a real
   WireGuard interface; a dummy interface is not a valid successful-apply test.
   Use fresh, separate data directories per arm and the same disposable CA.
   Never publish generated configurations, CA keys, or simulator key fixtures.
3. Use `gwtest.local`, proxy/RPC/admin ports `38400/38401/38402`, origin ports
   `38404/38405`, and the test-only admin token `benchmark-only`. Configure four
   RPC workers and four proxy workers, with thread-per-core and connection
   rebalance enabled. Disable recycle and cluster sync. Keep authorization
   disabled and `insecure_localhost_backend` enabled **only inside the isolated
   test namespace**. The `/25` client pool must have room for 64 instances.
4. Generate the client certificates in the disposable CA directory:

   ```bash
   python3 prepare_register_clients.py "$W/certs"
   ```

   Requires Python `msgpack` and OpenSSL. Existing client files are refused.
   Use these same certificates for both arms. The script does not print keys.
5. Pin the gateway to CPUs `0-7`, load/probe processes to `8-15`, origin to
   `16-19`, and simulator to `20-23` (adjust all arms equally on smaller hosts).
   Run only one gateway at a time. Do not compile or run other benchmarks while
   measuring. Start simulator, origin, and gateway as in the guide, inside the
   namespace. Give the gateway permission to configure its isolated interface.
6. From inside that namespace, run:

   ```bash
   taskset -c 8-15 python3 register_load.py \
     --certs "$W/certs" --arm before --seconds 15 --rounds 1 \
     --interface gwreg0 > before-1.jsonl
   ```

   Repeat for the new binary with `--arm after`. Run three repetitions per arm,
   restarting the gateway between runs; alternate order as before/after,
   after/before, before/after. All programs must remain inside the namespace.
   `--interface` is optional, but kernel convergence checking requires access to
   `wg show INTERFACE peers`. It never requests private keys.

## Workload and outputs

Every condition starts with the same 64 initialized instances and a one-second
settling period. Client certificates carry distinct AppInfo instance IDs.
Registrations use persistent mTLS connections, `health_check=false`, and a
reported unrestricted port policy (no guest-agent policy fetch traffic).
Conditions are idle; unchanged-key registration at concurrency 1, 16, and 64;
and a different public key on every request at concurrency 64. Public keys
are deterministic 32-byte test values; no CVM uses these peers for tunneling.

Info and proxy probes run in separate Python processes from the load generator,
so its event loop cannot artificially delay their timers. Both open a new TLS
connection per request. Proxy requests use SNI `localhost-38404.gwtest.local`
and `/bytes/1024`. That shortcut still exercises the routing-state lock through
port-policy checking, but bypasses actual CVM routing/handshakes.

JSONL records contain counts, errors, achieved rates, nearest-rank latency
percentiles, and WireGuard apply/failure counter deltas. Apply counts include a
one-second post-load drain. `convergence_after_load_ms` includes the time to
invoke `wg` and is an upper bound on final convergence after all measured
requests complete, **not** per-registration tunnel-readiness latency. A missed
final update fails the run rather than producing a successful benchmark record.

Registration responses now acknowledge local state before asynchronous
WireGuard convergence. A fixed 25 ms batch window precedes each background
apply; failed applies retry after one second, even with no new request. Neither
interval is a hard readiness bound: scheduler delay, render time, filesystem
latency, and `wg syncconf` execution time are additional. Startup and explicit
operator removal still wait for an apply and propagate errors.

An immediate first WireGuard handshake can race the asynchronous update. The
client's handshake retransmission schedule can therefore make end-to-end
readiness slower than the batch window. This benchmark checks final kernel
state, not that initial-handshake behavior. Existing unchanged peers are not
reconfigured by repeated registrations. External/manual edits to the interface
are not detected by the applied-config cache; restart or a changed desired
configuration is needed to reapply in that case.
