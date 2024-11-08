# Dstack

This project is Phala's opinionated implementation of Andrew's design of [Dstack](https://collective.flashbots.net/t/dstack-speedrunning-a-p2p-confidential-vm). It's highly experimental and evolving fast. We aim to merge it into a production ready project eventually.

# Overview

Components in Dstack:

- `teepod`: A service running in bare TDX host to manage CVMs
- `tproxy`: A reverse proxy to forward TLS connections to CVMs
- `kms`: A KMS server to generate keys for CVMs
- `tappd`: A service running in CVM to serve containers' key derivation and attestation requests
- `meta-dstack`: A Yocto meta layer to build CVM guest images

The overall architecture is shown below:
![arch](./docs/assets/arch.png)

# Directory structure

```text
dstack/
    kms/                         A prototype KMS server
    tappd/                       A service running in CVM to serve containers' key derivation and attestation requests.
    tdxctl/                      A CLI tool getting TDX quote, extending RTMR, generating cert for RA-TLS, etc.
    teepod/                      A service running in bare TDX host to manage CVMs
    tproxy/                      A reverse proxy to forward TLS connections to CVMs
    certbot/                     A tool to automatically obtain and renew TLS certificates for tproxy
    ra-rpc/                      RA-TLS support for pRPC
    ra-tls/                      RA-TLS support library
    tdx-attest/                  Guest library for getting TDX quote and extending RTMR
```

# Build and play locally

## Prerequisites

- A TDX host machine with Ubuntu 24.04 installed and has public IPv4 address
- A domain name you can modify DNS records

## Install dependencies

```bash
# for Ubuntu 24.04
sudo apt install -y build-essential chrpath diffstat lz4 wireguard-tools
# install rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Build and run

```bash
git clone https://github.com/Phala-Network/meta-dstack.git --recursive
cd meta-dstack/
source dev-setup
cd dstack/

# !!! When using Yocto, you need to ensure to run "build.sh" within the same
# !!! bash environment. Otherwise, you should always "source dev-setup" before
# !!! running "build.sh".

mkdir build
cd build
../build.sh
# This outputs the following message:
# Config file ../build-config.sh created, please edit it to configure the build

vim ../build-config.sh
```

Now edit the config file. The following configurations values must be changed properly according to your environment:

```bash
# The internal port for teepod to listen to requests from you
TEEPOD_RPC_LISTEN_PORT=9080
# The start CID for teepod to allocate to CVMs
TEEPOD_CID_POOL_START=20000

# The internal port for kms to listen to requests from CVMs
KMS_RPC_LISTEN_PORT=9043
# The internal port for tproxy to listen to requests from CVMs
TPROXY_RPC_LISTEN_PORT=9070

# WireGuard interface name for tproxy
TPROXY_WG_INTERFACE=tproxy-kvin
# WireGuard listening port for tproxy
TPROXY_WG_LISTEN_PORT=9182
# WireGuard server IP for tproxy
TPROXY_WG_IP=10.0.3.1
# WireGuard client IP range
TPROXY_WG_CLIENT_IP_RANGE=10.0.3.0/24
# The public port for tproxy to listen to requests that would be forwarded to app in CVMs
TPROXY_SERVE_PORT=9443

# The public domain name for tproxy. Please set a wildacard DNS record (e.g. *.app.kvin.wang in this example)
# for this domain that points the IP address of your TDX host.
TPROXY_PUBLIC_DOMAIN=app.kvin.wang
# The path to the TLS certificate for tproxy's public endpoint
TPROXY_CERT=/etc/rproxy/certs/cert.pem
# The path to the TLS key for tproxy's public endpoint
TPROXY_KEY=/etc/rproxy/certs/key.pem
```

Run build.sh again to build the artifacts.

```bash
../build.sh

# If everything is okay, you should see the built artifacts in the `build` directory.
$ ls
certs  images  kms  kms.toml  run  teepod  teepod.toml  tproxy  tproxy.toml

# The wireguard interface should be set up:
$ ifconfig tproxy-kvin
tproxy-kvin: flags=209<UP,POINTOPOINT,RUNNING,NOARP>  mtu 1420
        inet 10.0.3.1  netmask 255.255.255.0  destination 10.0.3.1
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 1000  (UNSPEC)
        RX packets 4839  bytes 839320 (839.3 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 3836  bytes 507540 (507.5 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

Now you can open 3 terminals to start the components:

1. Run `./kms`
2. Run `sudo ./tproxy`
3. Run `./teepod`

## Deploy an App
Open the teepod webpage [http://localhost:9080](http://localhost:9080)(change the port according to your configuration) on your local machine to deploy a `docker-compose.yaml` file:

![teepod](./docs/assets/teepod.png)

After the container deployed, it should need some time to start the CVM and the containers. Time would be vary depending on your workload.

- Click the [Logs] button to see the logs of the CVM, you can see if the container is finished starting there.

- Once the container is running, you can click the [Dashboard] button to see some information of the container. And the logs of the containers can be seen in the [Dashboard] page.

    ![tappd](./docs/assets/tappd.png)

- You can open tproxy's dashboard at [https://localhost:9070](https://localhost:9070) to see the CVM's wireguard ip address, as shown below:

![tproxy](./docs/assets/tproxy.png)

## Access the App

Once the app is deployed and listening on an HTTP port, you can access the HTTP service via tproxy's public domain. The ingress mapping rules are:

- `<id>[s].<base_domain>` maps to port `80` or `443` if with `s` in the CVM.
- `<id>-<port>[s].<base_domain>` maps to port `<port>` in the CVM.

For example, `3327603e03f5bd1f830812ca4a789277fc31f577-8080.app.kvin.wang` maps to port `8080` in the CVM.

Where the `<id>` can be either the app id or the instance id. If the app id is used, one of the instances will be selected by the load balancer.
If the `id-port` part ends with `s`, it means the TLS connection will be passthrough to the app rather than terminating at tproxy.

You can also ssh into the CVM to inspect more information, if your deployment uses the image `dstack-x.x.x-dev`:

```bash
# The IP address of the CVM can be found in the tproxy dashboard.
ssh root@10.0.3.2
```

## Getting TDX quote in docker container

To get a TDX quote within app containers:

1. Mount `/var/run/tappd.sock` to the target container in `docker-compose.yaml`

    ```yaml
    version: '3'
    services:
    nginx:
        image: nginx:latest
        volumes:
        - /var/run/tappd.sock:/var/run/tappd.sock
        ports:
        - "8080:80"
        restart: always
    ```

2. Execute the quote request command in the container.

    ```bash
    # The argument report_data accepts binary data encoding in hex string.
    # The actual report_data passing the to the underlying TDX driver is sha2_256(report_data).
    curl -X POST --unix-socket /var/run/tappd.sock -d '{"report_data": "0x1234deadbeef"}' http://localhost/prpc/Tappd.TdxQuote?json | jq .  
    ```

## Container logs

Container logs can be obtained from the CVM's `dashboard` page or by curl:

```bash
curl 'http://<appid>.app.kvin.wang:9090/logs/<container name>?since=0&until=0&follow=true&text=true&timestamps=true&bare=true'
```

Replace `<appid>` and `<container name>` with actual values. Available parameters:

- since=0: Starting Unix timestamp for log retrieval
- until=0: Ending Unix timestamp for log retrieval
- follow: Enables continuous log streaming
- text: Returns human-readable text instead of base64 encoding
- timestamps: Adds timestamps to each log line
- bare: Returns the raw log lines without json format

The response of the RPC looks like:
```
$ curl 'http://0.0.0.0:9190/logs/zk-provider-server?text&timestamps'
{"channel":"stdout","message":"2024-09-29T03:05:45.209507046Z Initializing Rust backend...\n"}
{"channel":"stdout","message":"2024-09-29T03:05:45.209543047Z Calling Rust function: init\n"}
{"channel":"stdout","message":"2024-09-29T03:05:45.209544957Z [2024-09-29T03:05:44Z INFO  rust_prover] Initializing...\n"}
{"channel":"stdout","message":"2024-09-29T03:05:45.209546381Z [2024-09-29T03:05:44Z INFO  rust_prover::groth16] Starting setup process\n"}
```

## Reverse proxy: TLS Passthrough

The build configuration for TLS Passthrough is:

```bash
TPROXY_LISTEN_PORT_PASSTHROUGH=9008
```

With this configuration, tproxy listens port `9008` for incoming TLS connections and forwards them to the appropriate Tapp based on `SNI`, where SNI represents your custom domain and the forwarding destination is determined by your DNS records.

For example, assuming I've deployed an app at `3327603e03f5bd1f830812ca4a789277fc31f577`, as shown below:

![appid](./docs/assets/appid.png)

Now, I want to use my custom domain `tapp-nginx.kvin.wang` to access the Tapp. I need to set up two DNS records with my DNS provider (Cloudflare in my case):

1. `A` or `CNAME` record to point the domain to the tdx machine:

    ![tapp-dns-a](./docs/assets/tapp-dns-a.png)

2. `TXT` record to instruct the Tproxy to direct the request to the specified Tapp:

    ![tapp-dns-txt](./docs/assets/tapp-dns-txt.png)

Where

`_tapp-address.tapp-nginx.kvin.wang` means configuring the tapp destination address of domain `tapp-nginx.kvin.wang`.

The TXT record value `3327603e03f5bd1f830812ca4a789277fc31f577:8043` means that requests sent to `tapp-nginx.kvin.wang` will be processed by Tapp `3327603e03f5bd1f830812ca4a789277fc31f577` on port `8043`

Given the config `TPROXY_LISTEN_PORT_PASSTHROUGH=9008`, now we can go to [`https://tapp-nginx.kvin.wang:9008`](https://tapp-nginx.kvin.wang:9008) and the request will be handled by the service listening on `8043` in Tapp `3327603e03f5bd1f830812ca4a789277fc31f577`.

## Upgrade an App

Got to the teepod webpage, click the [Upgrade] button, select or paste the compose file you want to upgrade to, and click the [Upgrade] button again.
Upon successful initiation of the upgrade, you'll see a message prompting you to run the following command in your terminal to authorize the upgrade through KMS:

```shell
./kms-allow-upgrade.sh <app_id> <upgraded_app_id>
```

The app id does not change after the upgrade. Stop and start the app to apply the upgrade.

## HTTPS Certificate Transparency

In the tutorial above, we used a TLS certificate with a private key external to the TEE (Tproxy-CVM here). To establish trust, we need to generate and maintain the certificate's private key within the TEE and provide evidence that all TLS certificates for the domain were originate solely from Tproxy-CVM.

By combining Certificate Transparency Logs and CAA DNS records, we can make best effort to minimize security risks. Here's our approach:

- Set CAA records to allow only the account created in Tproxy-CVM to request Certificates.
- Launch a program to monitor Certificate Transparency Log and give alarm once any certificate issued to a pubkey that isn’t generated by Tproxy.

### Configurations

To launch Certbot, you need to own a domain hosted on Cloudflare. Obtain an API token with DNS operation permissions from the Cloudflare dashboard. Configure it in the `build-config.sh`:

```bash
# The directory to store the auto obtained TLS certificate and key
TPROXY_CERT=${CERBOT_WORKDIR}/live/cert.pem
TPROXY_KEY=${CERBOT_WORKDIR}/live/key.pem

# for certbot
CF_ZONE_ID=cc0a40...
CF_API_TOKEN=g-DwMH...
# ACME_URL=https://acme-v02.api.letsencrypt.org/directory
ACME_URL=https://acme-staging-v02.api.letsencrypt.org/directory
```

Then re-run the ../build.sh:

```bash
../build.sh
```

### Launch certbot

Then run the certbot in the `build/` and you will see the following log:
```text
$ RUST_LOG=info,certbot=debug ./certbot renew -c certbot.toml
2024-10-25T07:41:00.682990Z  INFO certbot::bot: creating new ACME account
2024-10-25T07:41:00.869246Z  INFO certbot::bot: created new ACME account: https://acme-staging-v02.api.letsencrypt.org/acme/acct/168601853
2024-10-25T07:41:00.869270Z  INFO certbot::bot: setting CAA records
2024-10-25T07:41:00.869276Z DEBUG certbot::acme_client: setting guard CAA records for app.kvin.wang
2024-10-25T07:41:01.740767Z DEBUG certbot::acme_client: removing existing CAA record app.kvin.wang 0 issuewild "letsencrypt.org;validationmethods=dns-01;accounturi=https://acme-staging-v02.api.letsencrypt.org/acme/acct/168578683"
2024-10-25T07:41:01.991298Z DEBUG certbot::acme_client: removing existing CAA record app.kvin.wang 0 issue "letsencrypt.org;validationmethods=dns-01;accounturi=https://acme-staging-v02.api.letsencrypt.org/acme/acct/168578683"
2024-10-25T07:41:02.216751Z DEBUG certbot::acme_client: setting CAA records for app.kvin.wang, 0 issue "letsencrypt.org;validationmethods=dns-01;accounturi=https://acme-staging-v02.api.letsencrypt.org/acme/acct/168601853"
2024-10-25T07:41:02.424217Z DEBUG certbot::acme_client: setting CAA records for app.kvin.wang, 0 issuewild "letsencrypt.org;validationmethods=dns-01;accounturi=https://acme-staging-v02.api.letsencrypt.org/acme/acct/168601853"
2024-10-25T07:41:02.663824Z DEBUG certbot::acme_client: removing guard CAA records for app.kvin.wang
2024-10-25T07:41:03.095564Z DEBUG certbot::acme_client: generating new cert key pair
2024-10-25T07:41:03.095678Z DEBUG certbot::acme_client: requesting new certificates for *.app.kvin.wang
2024-10-25T07:41:03.095699Z DEBUG certbot::acme_client: creating new order
2024-10-25T07:41:03.250382Z DEBUG certbot::acme_client: order is pending, waiting for authorization
2024-10-25T07:41:03.283600Z DEBUG certbot::acme_client: creating dns record for app.kvin.wang
2024-10-25T07:41:04.027882Z DEBUG certbot::acme_client: challenge not found, waiting 500ms tries=2 domain="_acme-challenge.app.kvin.wang"
2024-10-25T07:41:04.600711Z DEBUG certbot::acme_client: challenge not found, waiting 1s tries=3 domain="_acme-challenge.app.kvin.wang"
2024-10-25T07:41:05.642300Z DEBUG certbot::acme_client: challenge not found, waiting 2s tries=4 domain="_acme-challenge.app.kvin.wang"
2024-10-25T07:41:07.715947Z DEBUG certbot::acme_client: challenge not found, waiting 4s tries=5 domain="_acme-challenge.app.kvin.wang"
2024-10-25T07:41:11.724831Z DEBUG certbot::acme_client: challenge not found, waiting 8s tries=6 domain="_acme-challenge.app.kvin.wang"
2024-10-25T07:41:19.815990Z DEBUG certbot::acme_client: challenge not found, waiting 16s tries=7 domain="_acme-challenge.app.kvin.wang"
2024-10-25T07:41:35.852790Z DEBUG certbot::acme_client: setting challenge ready for https://acme-staging-v02.api.letsencrypt.org/acme/chall-v3/14584884443/mQ-I2A
2024-10-25T07:41:35.934425Z DEBUG certbot::acme_client: challenges are ready, waiting for order to be ready
2024-10-25T07:41:37.972434Z DEBUG certbot::acme_client: order is ready, uploading csr
2024-10-25T07:41:38.052901Z DEBUG certbot::acme_client: order is processing, waiting for challenge to be accepted
2024-10-25T07:41:40.088190Z DEBUG certbot::acme_client: order is valid, getting certificate
2024-10-25T07:41:40.125988Z DEBUG certbot::acme_client: removing dns record 6ab5724e8fa7e3e8f14e93333a98866a
2024-10-25T07:41:40.377379Z DEBUG certbot::acme_client: stored new cert in /home/kvin/codes/meta-dstack/dstack/build/run/certbot/backup/2024-10-25T07:41:40.377174477Z
2024-10-25T07:41:40.377472Z  INFO certbot::bot: checking if certificate needs to be renewed
2024-10-25T07:41:40.377719Z DEBUG certbot::acme_client: will expire in Duration { seconds: 7772486, nanoseconds: 622281542 }
2024-10-25T07:41:40.377752Z  INFO certbot::bot: certificate /home/kvin/codes/meta-dstack/dstack/build/run/certbot/live/cert.pem is up to date
```

Where the command did are:

- Registered to letsencrypt and got a new account `https://acme-staging-v02.api.letsencrypt.org/acme/acct/168601853`
- Auto set CAA records for the domain on cloudflare, you can open the CF dashboard to see the record:

    ![certbot-caa](./docs/assets/certbot-caa.png)

- Auto requested a new certificate from Let's Encrypt. Automatically renews the certificate to maintain its validity

## Launch Tproxy

Execute tproxy with `sudo ./tproxy`, then access the web portal to check the Tproxy-CVM managed Let's Encrypt account. The account's private key remains securely sealed within the TEE.

![tproxy-accountid](./docs/assets/tproxy-accountid.png)

## Certificate transparency log monitor

To enhance security, we've limited TLS certificate issuance to Tproxy via CAA records. However, since these records can be modified through Cloudflare's domain management, we need to implement global CA certificate monitoring to maintain security oversight.

`ct_monitor` tracks Certificate Transparency logs via [https://crt.sh](https://crt.sh/?q=app.kvin.wang), comparing their public key with the ones got from Tproxy RPC. It immediately alerts when detecting unauthorized certificates not issued through Tproxy:

```text
$ ./ct_monitor -t https://localhost:9010/prpc -d app.kvin.wang
2024-10-25T08:12:11.366463Z  INFO ct_monitor: monitoring app.kvin.wang...
2024-10-25T08:12:11.366488Z  INFO ct_monitor: fetching known public keys from https://localhost:9010/prpc
2024-10-25T08:12:11.566222Z  INFO ct_monitor: got 2 known public keys
2024-10-25T08:12:13.142122Z  INFO ct_monitor: ✅ checked log id=14705660685
2024-10-25T08:12:13.802573Z  INFO ct_monitor: ✅ checked log id=14705656674
2024-10-25T08:12:14.494944Z ERROR ct_monitor: ❌ error in CTLog { id: 14666084839, issuer_ca_id: 295815, issuer_name: "C=US, O=Let's Encrypt, CN=R11", common_name: "kvin.wang", name_value: "*.app.kvin.wang", not_before: "2024-09-24T02:23:15", not_after: "2024-12-23T02:23:14", serial_number: "03ae796f56a933c8ff7e32c7c0d662a253d4", result_count: 1, entry_timestamp: "2024-09-24T03:21:45.825" }
2024-10-25T08:12:14.494998Z ERROR ct_monitor: error: certificate has issued to unknown pubkey: 30820122300d06092a864886f70d01010105000382010f003082010a02820101009de65c767caf117880626d1acc1ee78f3c6a992e3fe458f34066f92812ac550190a67e49ebf4f537003c393c000a8ec3e114da088c0cb02ffd0881fd39a2b32cc60d2e9989f0efab3345bee418262e0179d307d8d361fd0837f85d17eab92ec6f4126247e614aa01f4efcc05bc6303a8be68230f04326c9e85406fc4d234e9ce92089253b11d002cdf325582df45d5da42981cd546cbd2e9e49f0fa6636e747a345aaf8cefa02556aa258e1f7f90906be8fe51567ac9626f35bc46837e4f3203387fee59c71cea400000007c24e7537debc1941b36ff1612990233e4c219632e35858b1771f17a71944adf6c657dd7303583e3aeed199bd36a3152f49980f4f30203010001
```

# License

Copyright 2024 Phala Network.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)
