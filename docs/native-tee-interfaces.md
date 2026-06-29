# Advanced Native TEE Interfaces in Containers

Most applications should use the dstack API through `/var/run/dstack.sock`. Native TEE interfaces are available for advanced compatibility cases, such as unmodified binaries or libraries that already know how to use Linux TEE devices or configfs-tsm.

The examples below use Compose syntax because dstack currently accepts Compose files for container configuration.

## Choose an Interface

Use native interfaces only when your application already depends on them. If you control the application code, prefer the dstack SDK or HTTP API because it also returns dstack metadata, event logs, and verification inputs.

| Interface | Platform | Use when |
| --- | --- | --- |
| `/var/run/dstack.sock` | dstack-supported TEEs | Your application can call the dstack SDK or HTTP API |
| `/dev/tdx_guest` | Intel TDX | Existing software expects the Linux TDX guest device |
| `/dev/sev-guest` | AMD SEV-SNP | Existing software expects the Linux SEV-SNP guest device |
| `/sys/kernel/config/tsm/report` | Intel TDX and AMD SEV-SNP, when supported by the deployed OS image | Existing software expects configfs-tsm `inblob` and `outblob` report generation |

The native report formats are platform-specific. Intel TDX returns TDX quote or report data, depending on the interface and library. AMD SEV-SNP returns an SNP attestation report and, for extended report flows, certificate data.

## Version Availability

The versions below refer to the dstack OS image version, not an SDK or service binary version.

| Native interface | Available from |
| --- | --- |
| `/dev/tdx_guest` | dstack OS v0.5.0 on Intel TDX images. The v0.5.x images expose it through the bundled `tdx-guest` kernel module. The v0.6.0.a1 images and later use the in-tree Linux TDX guest driver. |
| TDX configfs-tsm at `/sys/kernel/config/tsm/report` | dstack OS v0.6.0.a1 and later on Intel TDX. It is not available in v0.5.x TDX images. |
| `/dev/sev-guest` | dstack OS v0.6.0 SEV-SNP image line and later on AMD SEV-SNP. It is not available in v0.5.x TDX images. |
| SEV-SNP configfs-tsm at `/sys/kernel/config/tsm/report` | dstack OS v0.6.0 SEV-SNP image line and later on AMD SEV-SNP, when the deployed image enables the Linux TSM report interface. |

## Learn the Native Linux APIs

These interfaces are Linux kernel ABIs, not dstack-specific APIs. Use the upstream documentation when you need ioctl structures, configfs file semantics, or provider-specific report formats:

| API | Official reference |
| --- | --- |
| Intel TDX guest device | [TDX Guest API Documentation](https://docs.kernel.org/virt/coco/tdx-guest.html) |
| AMD SEV-SNP guest device | [SEV Guest API Documentation](https://docs.kernel.org/virt/coco/sev-guest.html) |
| configfs-tsm report ABI | [configfs-tsm report ABI](https://www.kernel.org/doc/Documentation/ABI/testing/configfs-tsm) |

## Use the dstack API by Default

Mount the dstack socket when your application can use the dstack SDK or HTTP API:

```yaml
services:
  app:
    image: your-image
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
```

The dstack API is the normal application interface for quotes, keys, application information, and runtime events. See the [Guest Agent RPC API](../sdk/curl/api.md) for request and response details.

## Expose Intel TDX Interfaces

For TDX software that expects the Linux TDX guest device, expose `/dev/tdx_guest` to the container:

```yaml
services:
  app:
    image: your-image
    devices:
      - /dev/tdx_guest:/dev/tdx_guest
```

For TDX software that expects configfs-tsm, mount the TSM configfs subtree:

```yaml
services:
  app:
    image: your-image
    volumes:
      - /sys/kernel/config/tsm:/sys/kernel/config/tsm
```

Most configfs-tsm libraries create a report entry under `/sys/kernel/config/tsm/report`, write report data to `inblob`, and read the generated quote or report from `outblob`.

## Expose AMD SEV-SNP Interfaces

For SEV-SNP software that expects the Linux SEV guest device, expose `/dev/sev-guest` to the container:

```yaml
services:
  app:
    image: your-image
    devices:
      - /dev/sev-guest:/dev/sev-guest
```

For SEV-SNP software that expects configfs-tsm, mount the same TSM configfs subtree:

```yaml
services:
  app:
    image: your-image
    volumes:
      - /sys/kernel/config/tsm:/sys/kernel/config/tsm
```

On SEV-SNP, configfs-tsm exposes SNP report generation through the common Linux TSM report ABI. Provider-specific attributes and output files can differ from TDX. Check the library you are running for the exact files it reads.

## Permissions

Root containers can use root-owned device and configfs paths once they are exposed to the container. If your image switches to a non-root user, set up access before the non-root process starts.

For device files, a root entrypoint can relax permissions and then launch the application:

```yaml
services:
  app:
    image: your-image
    devices:
      - /dev/tdx_guest:/dev/tdx_guest
    command: sh -lc 'chmod 666 /dev/tdx_guest && exec /app/start'
```

If the main process must stay non-root from the start, use a small root helper container to adjust the host device node before the application starts:

```yaml
services:
  tdx-device-perms:
    image: busybox
    volumes:
      - /dev/tdx_guest:/dev/tdx_guest
    command: chmod 666 /dev/tdx_guest
    restart: "no"

  app:
    image: your-image
    user: "1000:1000"
    depends_on:
      tdx-device-perms:
        condition: service_completed_successfully
    devices:
      - /dev/tdx_guest:/dev/tdx_guest
```

For AMD SEV-SNP, use the same pattern with `/dev/sev-guest`.

For configfs-tsm, permissions can be more provider-specific. If your main process must remain non-root, keep the native ABI access in a small root helper process and expose only the operation your application needs over local IPC.

## Intel TDX RTMR3 Measurements

On TDX, RTMR3 is an append-only runtime measurement register. It is useful when a launcher measures code or configuration first, then hands permission and execution to the measured code.

Use `/EmitEvent` through `/var/run/dstack.sock` when you want dstack's event log and verifier to replay an application runtime measurement. If your application extends RTMR3 directly through native interfaces, your application owns the event-log story for those extensions.
