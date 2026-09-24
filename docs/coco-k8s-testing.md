# Testing the dstack CoCo guest image on Kubernetes

This guide smoke-tests the dstack rootfs as a Kata/CoCo CVM guest image on a
Kubernetes node.  It is intended for the first-cut CoCo integration where the
native dstack services and the CoCo guest components run independently in the
same image.

The commands below assume a local Yocto build tree and a single-node test host.
Adjust paths and the `RuntimeClass` name if your Kata installation differs.

## Prerequisites

- A host with Kubernetes and Kata Containers installed.
- A confidential Kata runtime class, for example `kata-qemu-tdx`.
- The node is labelled for Kata scheduling, for example:

  ```bash
  kubectl get runtimeclass
  kubectl get nodes --show-labels | grep katacontainers.io/kata-runtime=true
  ```

- The host can write to the Kata image/config directories, typically:

  ```text
  /opt/kata/share/kata-containers/
  /opt/kata/share/defaults/kata-containers/configuration-qemu-tdx.toml
  ```

> **Warning:** the test edits the host Kata runtime config. Use a dedicated test
> machine or keep a backup and restore it when finished.

## Build the guest rootfs

```bash
source os/yocto/dev-setup os/yocto/bb-build >/dev/null
bitbake dstack-rootfs
```

The build should produce:

```text
os/yocto/bb-build/tmp/deploy/images/dstack/dstack-rootfs-dstack.cpio
os/yocto/bb-build/tmp/deploy/images/dstack/bzImage
```

Before building a disk image, verify that the CoCo/Kata pieces are present in
the rootfs work directory:

```bash
ROOT=os/yocto/bb-build/tmp/work/dstack-poky-linux/dstack-rootfs/1.0/rootfs

test -x "$ROOT/usr/bin/kata-agent"
test -f "$ROOT/etc/kata-opa/default-policy.rego"
test -f "$ROOT/etc/ocicrypt_config.json"
test -x "$ROOT/pause_bundle/rootfs/pause"
```

The default policy file is required because the `agent-policy` feature
initializes OPA before initdata is parsed.  The pause bundle is required by
Kata's confidential/guest-pull sandbox path.

## Create a Kata disk image from the built cpio

```bash
IMG=/opt/kata/share/kata-containers/dstack-coco-mvp.ext4
KERNEL=/opt/kata/share/kata-containers/vmlinuz-dstack-coco-mvp
CPIO=$(readlink -f os/yocto/bb-build/tmp/deploy/images/dstack/dstack-rootfs-dstack.cpio)
BZIMAGE=$(readlink -f os/yocto/bb-build/tmp/deploy/images/dstack/bzImage)
MNT=/tmp/dstack-coco-mvp-root

sudo rm -f "${IMG}.tmp"
sudo truncate -s 3G "${IMG}.tmp"
printf 'label: dos\nunit: sectors\n\nstart=6144, type=83, bootable\n' | sudo sfdisk "${IMG}.tmp"

LOOP=$(sudo losetup --find --show --partscan "${IMG}.tmp")
sleep 1
sudo mkfs.ext4 -F "${LOOP}p1"
sudo mkdir -p "$MNT"
sudo mount "${LOOP}p1" "$MNT"

sudo bash -c "cd '$MNT' && cpio -idmu --no-absolute-filenames < '$CPIO'"
sudo sync
sudo umount "$MNT"
sudo losetup -d "$LOOP"

sudo mv -f "${IMG}.tmp" "$IMG"
sudo cp -a "$BZIMAGE" "$KERNEL"
```

If your system does not create `${LOOP}p1`, detach the loop device and use an
explicit offset mount/mkfs flow instead.

## Point Kata TDX at the dstack image

Back up the current config first:

```bash
KATA_CFG=/opt/kata/share/defaults/kata-containers/configuration-qemu-tdx.toml
sudo cp -a "$KATA_CFG" "${KATA_CFG}.bak.$(date +%Y%m%d%H%M%S)"
```

Set the kernel/image/rootfs and make sure the agent starts the CoCo guest
components:

```bash
sudo sed -i \
  -e 's#^kernel = ".*"#kernel = "/opt/kata/share/kata-containers/vmlinuz-dstack-coco-mvp"#' \
  -e 's#^image = ".*"#image = "/opt/kata/share/kata-containers/dstack-coco-mvp.ext4"#' \
  -e 's#^rootfs_type=.*#rootfs_type="ext4"#' \
  -e 's#^default_memory = .*#default_memory = 4096#' \
  "$KATA_CFG"

# Add these to kernel_params if they are not already present:
# cgroup_no_v1=all systemd.unified_cgroup_hierarchy=1
# systemd.unit=kata-containers.target
# agent.log=debug
# agent.guest_components_procs=api-server-rest
# agent.guest_components_rest_api=all
```

Kata normally reads this config when a new sandbox starts.  If the runtime has a
stale config, restart containerd/kubelet on the test node.

## Create initdata

For a smoke test, use an allow-all policy and offline CDH config:

```bash
cat >/tmp/dstack-coco-mvp-initdata.toml <<'EOF_INITDATA'
version = "0.1.0"
algorithm = "sha256"

[data]
"aa.toml" = '''
[eventlog_config]
init_pcr = 17
enable_eventlog = false

[log]
level = "debug"
'''

"cdh.toml" = '''
socket = "unix:///run/confidential-containers/cdh.sock"

[kbc]
name = "offline_fs_kbc"
url = ""

[log]
level = "debug"
'''

"policy.rego" = '''
package agent_policy

default AddARPNeighborsRequest := true
default AddSwapRequest := true
default CloseStdinRequest := true
default CopyFileRequest := true
default CreateContainerRequest := true
default CreateSandboxRequest := true
default DestroySandboxRequest := true
default ExecProcessRequest := true
default GetDiagnosticDataRequest := true
default GetMetricsRequest := true
default GetOOMEventRequest := true
default GuestDetailsRequest := true
default ListInterfacesRequest := true
default ListRoutesRequest := true
default MemAgentCompactConfig := true
default MemAgentMemcgConfig := true
default MemHotplugByProbeRequest := true
default OnlineCPUMemRequest := true
default PauseContainerRequest := true
default PullImageRequest := true
default ReadStreamRequest := true
default RemoveContainerRequest := true
default RemoveStaleVirtiofsShareMountsRequest := true
default ReseedRandomDevRequest := true
default ResumeContainerRequest := true
default SetGuestDateTimeRequest := true
default SetPolicyRequest := true
default SignalProcessRequest := true
default StartContainerRequest := true
default StartTracingRequest := true
default StatsContainerRequest := true
default StopTracingRequest := true
default TtyWinResizeRequest := true
default UpdateContainerRequest := true
default UpdateEphemeralMountsRequest := true
default UpdateInterfaceRequest := true
default UpdateRoutesRequest := true
default WaitProcessRequest := true
default WriteStreamRequest := true
'''
EOF_INITDATA

INITDATA_B64=$(gzip -c /tmp/dstack-coco-mvp-initdata.toml | base64 -w0)
```

For a KBS-backed run, change `cdh.toml` to select `cc_kbc` and set the KBS URL,
then regenerate `INITDATA_B64`.

## Deploy the test Pod

```bash
cat >/tmp/dstack-coco-mvp-test.yaml <<EOF_POD
apiVersion: v1
kind: Pod
metadata:
  name: dstack-coco-mvp-test
  annotations:
    io.katacontainers.config.hypervisor.cc_init_data: "${INITDATA_B64}"
    io.katacontainers.config.hypervisor.default_memory: "4096"
    io.katacontainers.config.hypervisor.kernel_params: >-
      cgroup_no_v1=all
      systemd.unified_cgroup_hierarchy=1
      systemd.unit=kata-containers.target
      agent.log=debug
      agent.guest_components_procs=api-server-rest
      agent.guest_components_rest_api=all
spec:
  runtimeClassName: kata-qemu-tdx
  restartPolicy: Never
  containers:
  - name: test
    image: docker.io/library/busybox:latest
    imagePullPolicy: IfNotPresent
    command: ["sh", "-c", "echo hello-from-dstack-coco; uname -a; sleep 300"]
EOF_POD

kubectl apply -f /tmp/dstack-coco-mvp-test.yaml
kubectl get pod dstack-coco-mvp-test -w
```

A successful run reaches `Running`, and the container log shows the dstack guest
kernel:

```bash
kubectl logs dstack-coco-mvp-test
# hello-from-dstack-coco
# Linux dstack-coco-mvp-test 6.18.24-dstack ... x86_64 GNU/Linux
```

You can also confirm the QEMU command line uses the dstack image:

```bash
pgrep -af 'qemu-system.*sandbox' | grep dstack-coco-mvp
```

## Troubleshooting

- `timed out connecting to vsock ...:1024`: check the guest console and make
  sure `/etc/kata-opa/default-policy.rego` exists in the image.
- `Pause image not present in rootfs`: check that `/pause_bundle/config.json`
  and `/pause_bundle/rootfs/pause` exist in the image.
- `Creating watcher returned error too many open files`: the test host may have
  too many stale shims or a low inotify limit.  On a dedicated test node:

  ```bash
  sudo sysctl -w fs.inotify.max_user_instances=1024
  sudo sysctl -w fs.inotify.max_user_watches=1048576
  ```

- To remove a stuck test sandbox, first delete the Pod, then check for stale
  Kata shims/QEMU processes before killing anything:

  ```bash
  kubectl delete pod dstack-coco-mvp-test --force --grace-period=0 --ignore-not-found
  pgrep -af 'containerd-shim-kata|qemu-system.*sandbox'
  ```

## Cleanup

```bash
kubectl delete pod dstack-coco-mvp-test --force --grace-period=0 --ignore-not-found
```

Restore the backed-up Kata config when done:

```bash
sudo cp -a /path/to/configuration-qemu-tdx.toml.bak.YYYYmmddHHMMSS \
  /opt/kata/share/defaults/kata-containers/configuration-qemu-tdx.toml
sudo systemctl restart containerd
sudo systemctl restart kubelet
```
