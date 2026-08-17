# Experimental systemd VM process manager

The VMM can experimentally launch each VM as a transient systemd service instead
of sending the process to the standalone dstack supervisor. This gives every VM
its own cgroup and lets systemd retain ownership while QEMU performs a long
kernel-side shutdown, such as encrypted-memory teardown.

Enable it in the VMM configuration:

```toml
[cvm]
pm = "auto"

[systemd]
user = false
unit_prefix = "dstack-vm"
state_dir = "/var/lib/dstack-vmm/systemd-processes"
stop_timeout = "infinity"
```

The three process-manager modes are:

- `supervisor`: launch and manage every VM through the standalone Supervisor.
- `systemd`: launch and manage every VM as a transient systemd service.
- `auto`: use systemd for every new launch. When the VMM starts, VM processes
  already running in Supervisor are pinned to Supervisor for their remaining
  lifecycle. Their next VM launch removes the stopped Supervisor record and
  migrates them to systemd.

The default is `supervisor`, preserving existing deployments. Use `auto` for
transitions from Supervisor. Direct `systemd` mode refuses to start when it can
verify that Supervisor still owns running VMs.

## Runtime model

The VMM invokes `systemd-run` directly. A service is named from the configured
prefix and the SHA-256 digest of the VM ID:

```text
dstack-vm-<sha256(vm-id)>.service
```

By default, the VMM connects to the system service manager. Set `user = true`
to use the service manager of the user running the VMM instead. This passes
`--user` to every `systemd-run` and `systemctl` invocation. The user's systemd
manager and D-Bus session must remain available (for example, enable lingering
with `loginctl enable-linger <user>` when services must survive logout).

For a software-TPM VM, the service cgroup contains:

```text
vm-launcher
├── qemu
└── swtpm
```

The transient service uses these properties:

```ini
Type=exec
ExitType=cgroup
KillMode=mixed
KillSignal=SIGTERM
SendSIGKILL=yes
TimeoutStopSec=<systemd.stop_timeout>
Restart=no
```

The existing launcher remains responsible for swtpm readiness and graceful
child shutdown. systemd owns the final cgroup lifetime. A stop request is
submitted asynchronously so the VMM can report a VM as stopping while QEMU is
still completing kernel teardown.

The default stop timeout is `infinity` because large encrypted-memory guests
can spend hours in kernel teardown. Operators that prefer bounded escalation
can set a systemd time span such as `stop_timeout = "30min"`.

Process metadata is persisted in `systemd.state_dir`. It is required because a
successful transient unit may be garbage-collected after exit, while the VMM
still needs the original process annotation and CID during reconciliation.
When left empty, it defaults to `~/.dstack-vmm/systemd-processes`.

## Inspecting a VM

```bash
systemctl list-units 'dstack-vm-*.service' --all
systemctl show dstack-vm-<digest>.service \
  -p ActiveState -p SubState -p MainPID -p ControlGroup
systemd-cgls /system.slice/dstack-vm-<digest>.service
```

In user mode, add `--user` to the `systemctl` commands. The control group is
under the user's subtree of `user.slice`; use the `ControlGroup` value reported
by `systemctl --user show` rather than assuming a fixed path.

The implementation currently uses the `systemd-run` and `systemctl` CLIs. A
future production implementation should use the systemd D-Bus API directly for
atomic property handling and event-driven state updates.

## Limitations

- The host must run systemd with support for `ExitType=cgroup` and
  `StandardOutput=append:`.
- In system mode, the VMM must be authorized to create and stop system services.
- In user mode, the user service manager and its D-Bus socket must be available.
- Transient services inherit the systemd manager environment rather than the
  VMM environment. Variables in `ProcessConfig.env` are forwarded; unrelated
  inherited variables are not.
- Unit status is currently polled through `systemctl show`.
- If Supervisor becomes unavailable during an `auto` migration, pinned VMs
  retain their cached state to prevent double launch and CID reuse. Their
  stop/removal may remain pending until Supervisor is restored.
- `systemd.stop_timeout` syntax is validated by systemd when the first VM is
  launched; an invalid time span causes that launch to fail.
- Start and stop are not yet transactional with the metadata file.
- A host reboot removes transient units; normal VMM workdir recovery recreates
  services for VMs marked for automatic start.
