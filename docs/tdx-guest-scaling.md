# TDX guest scaling knobs

Many-vCPU TDX guests can run synchronization-heavy workloads (thread pools,
PyTorch CPU operators, `docker pull` extraction) several times slower than the
same guest without TDX. Most of the gap is wakeup overhead: every IPI and every
idle HLT costs a TD exit and a TD entry, which is several times more expensive
than an ordinary VM exit, and on large guests the cost grows further when many
vCPUs exit at the same time.

The dstack guest kernel has three runtime switches for this.

| Switch | Default | Where | Effect |
| --- | --- | --- | --- |
| `tdx_wake_q_batch` | on in TDX guests | `/sys/module/kernel/parameters/tdx_wake_q_batch` (also a boot parameter) | `wake_up_q()` (futex wake, condition variable broadcast, OpenMP pools) publishes wakeups immediately but sends the notification IPIs for up to 8 wakees as one mask IPI. Enabled at the end of boot. |
| `tdx_pv_single_ipi` | on in TDX guests | `/sys/module/kernel/parameters/tdx_pv_single_ipi` (also a boot parameter) | Single-target function IPIs use the KVM PV IPI hypercall instead of an emulated x2APIC ICR write. |
| `cpuidle_haltpoll` module | not loaded | `modprobe cpuidle_haltpoll force=1` / `rmmod cpuidle_haltpoll` | Idle vCPUs poll in the guest before halting. Wakeups that arrive during the window need neither an IPI nor a TD exit, at the cost of CPU spent polling. |

The two kernel switches cannot be enabled outside a TDX guest, so ordinary VMs
are unaffected. Boot with `tdx_wake_q_batch=0 tdx_pv_single_ipi=0`
(or write `N` to the sysfs files) to get the previous behavior.

The haltpoll governor parameters stay available under
`/sys/module/haltpoll/parameters/`. For TDX, a fixed window that does not
shrink works best (`guest_halt_poll_allow_shrink=N`,
`guest_halt_poll_grow_start` equal to `guest_halt_poll_ns`); the default
adaptive window tends to collapse to zero under slow wakeups and stay there.

## Profiles

| Profile | Settings | When |
| --- | --- | --- |
| default | kernel defaults: no guest polling, `tdx_wake_q_batch=Y`, `tdx_pv_single_ipi=Y` | all guests; no extra idle CPU |
| throughput | haltpoll module with a non-shrinking window, `tdx_wake_q_batch=Y`, `tdx_pv_single_ipi=N` | vCPUs are not overcommitted and throughput matters more than idle CPU |
| off | all switches off | reference behavior before these patches |

Measured poll windows for `throughput`: 200 µs for a 32-vCPU guest and 4 ms
for a 248-vCPU guest. Both are roughly 20-25 times the TD exit round trip
observed at that vCPU concurrency; values in between are interpolations.

Polling costs CPU while vCPUs idle-poll. Compared with an ordinary VM running
the same image, a `throughput` TD used about 0.15-0.2 extra host cores at idle
or at 200 requests per second, independent of vCPU count (4-32 vCPUs), and
about 0.9 cores more than `default` at 32 vCPUs with every vCPU 5% busy. The
`default` profile stayed within 0.02 cores of `off` in the same tests.

## Helper script

The image ships `/usr/lib/dstack/tdx-guest-tune.sh`, which applies one of the
profiles above, picks the poll window from the vCPU count, and prints the
resulting state:

```bash
/usr/lib/dstack/tdx-guest-tune.sh throughput   # or: default, off, status
/usr/lib/dstack/tdx-guest-tune.sh throughput --poll-us 1000 --pv-single Y
```

It refuses to run outside a TDX guest unless `--force` is given, and fails with
a message if the kernel lacks one of the switches.

The script is experimental and may be removed from future images; the kernel
switches above are the stable interface. It is outside `PATH` for that reason.
When calling it from an app's `pre_launch_script`, guard the call so the app
still starts on images without the script (the pre-launch script runs under
`set -e`):

```bash
t=/usr/lib/dstack/tdx-guest-tune.sh
if [ -x "$t" ]; then "$t" throughput || echo "tdx-guest-tune failed, continuing"; fi
```

## Boot time of large guests

Two always-on guest kernel patches keep the boot time of many-vCPU TDs from
growing with the square of the vCPU count on hosts that map TD private memory
at 4K only (upstream TDX KVM, 7.0):

- `0009` stops the page allocator from accepting 4 MiB of unaccepted memory on
  every allocation before the zone watermarks are initialized. Before, SMP
  bring-up of a 248-vCPU TD accepted about 13 GiB one 4K page at a time.
- `0010` converts the default SWIOTLB buffer to shared at `fs_initcall_sync`
  instead of before SMP bring-up. Before, the host had to force every
  still-spinning AP out of the TD for each of the buffer's 262144 pages.

A 248-vCPU, 32 GiB TD on a Granite Rapids host with a 7.0 kernel reaches init in
about 40-50 seconds instead of 575-680 seconds. The SWIOTLB size is unchanged.

## Observed results

Emerald Rapids host, 32-vCPU guest, the same image as TD and as an ordinary VM,
switches changed at runtime on one TD boot, two alternating rounds (MiB/s; docker
in seconds):

| Workload | Ordinary VM | TD `off` | TD `default` |
| --- | ---: | ---: | ---: |
| pool 1x32 | 2063 | 78 | 644 |
| PyTorch PASSIVE 1x32 | 2976 | 61 | 460 |
| pool 8x32 | 13137 | 2071 | 3852 |
| pool 4x8 | 37989 | 3612 | 12746 |
| PyTorch PASSIVE 8x32, 2 ms sleep | 784 | 478 | 656 |
| pool 1x4 | 11056 | 2129 | 5082 |
| `docker pull python:3.12`, local registry (s) | 29.6 | 48.0 | 43.5 |
| Geometric mean vs ordinary VM | 100% | 13.6% | 38.5% |

`default` was not slower than `off` on any workload, and timer and request
wakeup latency stayed comparable. The `throughput` profile closes more of the
remaining gap on wakeup-heavy workloads in exchange for polling CPU. Results
depend on workload shape.
