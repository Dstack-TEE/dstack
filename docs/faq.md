# FAQ

## CVM status turns to `exited` immediately

First, check the stderr output of the CVM.

> [!TIP]
> To view the CVM's stderr, append `ch=stderr` to the end of the log URL.
> If the log URL is `/logs?id=<uuid>&follow=true&ansi=false&lines=20`
> The stderr URL would be `/logs?id=<uuid>&follow=true&ansi=false&lines=20&ch=stderr`.

If you see an error message in CVM's stderr output:

```
Could not access KVM kernel module: Permission denied
gemu-system-x86_64: -accel kvm: failed to initialize kvm: Permission denied
```

This means your supervisor is not running with an account that belongs to the `libvirt` and `kvm` groups. You need to ensure your account is added to these two groups. You can check this by running the following command:

```shell
id
```

If you are not in these groups, you likely won't have the necessary privileges to run QEMU.

Once you have the required privileges, make sure the supervisor process is shut down:

```shell
ps aux | grep supervisor | grep $(whoami) | grep -v grep
```

Log out of all your sessions and log back in. Check your groups with the `id` command, and this should resolve the issue.
