# dstack Usage Guide

This guide covers deploying and managing applications on dstack. For infrastructure setup and self-hosting, see the [Deployment Guide](./deployment.md).

You can manage VMs via the dashboard or [CLI](./vmm-cli-user-guide.md).

## Deploy an App

Open the dstack-vmm webpage [http://localhost:9080](http://localhost:9080) (change the port according to your configuration) on your local machine to deploy a `docker-compose.yaml` file:

<div align="center">
<img src="./assets/vmm.png" alt="VMM Interface" height="400">
</div>

After the container is deployed, it should take some time to start the CVM and the containers. Time would vary depending on your workload.

- **[Logs]**: Click this button to view the CVM logs and monitor container startup progress
- **[Dashboard]**: Once the container is running, click this button to view container information and logs. (Note: This button is only visible when dstack-gateway is enabled. If disabled, you'll need to add a port mapping to port 8090 to access the CVM dashboard)

<div align="center">
<img src="./assets/guest-agent.png" alt="Guest Agent Dashboard" height="300">
</div>

## Pass Secrets to Apps

When deploying a new App, you can pass private data via Encrypted Environment Variables. These variables can be referenced in the docker-compose.yaml file as shown below:

<div align="center">
<img src="./assets/secret.png" alt="Secret Management" height="300">
</div>

The environment variables will be encrypted on the client-side and decrypted in the CVM before being passed to the containers.

## Access the App

Once your app is deployed and listening on an HTTP port, you can access it through dstack-gateway's public domain using these ingress mapping rules:

- `<id>[-[<port>][s|g]].<base_domain>` maps to port `<port>` in the CVM

**Examples:**

- `3327603e03f5bd1f830812ca4a789277fc31f577-8080.test0.dstack.org` - port `8080` (TLS termination to any TCP)
- `3327603e03f5bd1f830812ca4a789277fc31f577-8080g.test0.dstack.org` - port `8080` (TLS termination with HTTP/2 negotiation)
- `3327603e03f5bd1f830812ca4a789277fc31f577-8080s.test0.dstack.org` - port `8080` (TLS passthrough to any TCP)

The `<id>` can be either the app ID or instance ID. When using the app ID, the load balancer will select one of the available instances. Adding an `s` suffix enables TLS passthrough to the app instead of terminating at dstack-gateway. Adding a `g` suffix enables HTTPS/2 with TLS termination for gRPC applications.

**Note:** If dstack-gateway is disabled, you'll need to use port mappings configured during deployment to access your application via the host's IP address and mapped ports.

For development images (`dstack-x.x.x-dev`), you can SSH into the CVM for inspection:

```bash
# Find the CVM wg IP address in the dstack-vmm dashboard
ssh root@10.0.3.2
```

## Getting TDX Quote in Docker Container

To get a TDX quote within app containers:

**1. Mount the socket in `docker-compose.yaml`**

```yaml
version: '3'
services:
  nginx:
    image: nginx:latest
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
    ports:
      - "8080:80"
    restart: always
```

**2. Execute the quote request command**

```bash
# The argument report_data accepts binary data encoding in hex string.
# The actual report_data passing to the underlying TDX driver is sha2_256(report_data).
curl --unix-socket /var/run/dstack.sock http://localhost/GetQuote?report_data=0x1234deadbeef | jq .
```

## Container Logs

Container logs can be obtained from the CVM's `dashboard` page or by curl:

```bash
curl 'http://<appid>.<the domain you set for dstack-gateway>:9090/logs/<container name>?since=0&until=0&follow=true&text=true&timestamps=true&bare=true'
```

Replace `<appid>` and `<container name>` with actual values. Available parameters:

| Parameter | Description |
|-----------|-------------|
| `since=0` | Starting Unix timestamp for log retrieval |
| `until=0` | Ending Unix timestamp for log retrieval |
| `follow` | Enables continuous log streaming |
| `text` | Returns human-readable text instead of base64 encoding |
| `timestamps` | Adds timestamps to each log line |
| `bare` | Returns the raw log lines without json format |

**Example response:**
```bash
$ curl 'http://0.0.0.0:9190/logs/zk-provider-server?text&timestamps'
{"channel":"stdout","message":"2024-09-29T03:05:45.209507046Z Initializing Rust backend...\n"}
{"channel":"stdout","message":"2024-09-29T03:05:45.209543047Z Calling Rust function: init\n"}
{"channel":"stdout","message":"2024-09-29T03:05:45.209544957Z [2024-09-29T03:05:44Z INFO  rust_prover] Initializing...\n"}
{"channel":"stdout","message":"2024-09-29T03:05:45.209546381Z [2024-09-29T03:05:44Z INFO  rust_prover::groth16] Starting setup process\n"}
```

## TLS Passthrough with Custom Domain

dstack-gateway supports TLS passthrough for custom domains.

See the example [here](https://github.com/Dstack-TEE/dstack-examples/tree/main/custom-domain/dstack-ingress) for more details.

## Upgrade an App

Go to the dstack-vmm webpage, click the **[Upgrade]** button, select or paste the compose file you want to upgrade to, and click the **[Upgrade]** button again. The app id does not change after the upgrade. Stop and start the app to apply the upgrade.
