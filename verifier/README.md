# dstack-verifier

A HTTP server that provides dstack quote verification services using the same verification process as the dstack KMS.

## API Endpoints

### POST /verify

Verifies a dstack quote with the provided quote and VM configuration. The body can be grabbed via [getQuote](https://github.com/Dstack-TEE/dstack/blob/master/sdk/curl/api.md#3-get-quote).

**Request Body:**
```json
{
  "quote": "hex-encoded-quote",
  "event_log": "hex-encoded-event-log",
  "vm_config": "json-vm-config-string",
}
```

**Response:**
```json
{
  "is_valid": true,
  "details": {
    "quote_verified": true,
    "event_log_verified": true,
    "os_image_hash_verified": true,
    "report_data": "hex-encoded-64-byte-report-data",
    "tcb_status": "OK",
    "advisory_ids": [],
    "app_info": {
      "app_id": "hex-string",
      "compose_hash": "hex-string",
      "instance_id": "hex-string",
      "device_id": "hex-string",
      "mrtd": "hex-string",
      "rtmr0": "hex-string",
      "rtmr1": "hex-string",
      "rtmr2": "hex-string",
      "rtmr3": "hex-string",
      "mr_system": "hex-string",
      "mr_aggregated": "hex-string",
      "os_image_hash": "hex-string",
      "key_provider_info": "hex-string"
    }
  },
  "reason": null
}
```

### GET /health

Health check endpoint that returns service status.

**Response:**
```json
{
  "status": "ok",
  "service": "dstack-verifier"
}
```

## Configuration
You usually don't need to edit the config file. Just using the default is fine, unless you need to deploy your cunstomized os images.

### Configuration Options

- `host`: Server bind address (default: "0.0.0.0")
- `port`: Server port (default: 8080)
- `image_cache_dir`: Directory for cached OS images (default: "/tmp/dstack-verifier/cache")
- `image_download_url`: URL template for downloading OS images (default: Dstack official releases URL)
- `image_download_timeout_secs`: Download timeout in seconds (default: 300)
- `pccs_url`: Optional PCCS URL for quote verification

### Example Configuration File

```toml
host = "0.0.0.0"
port = 8080
image_cache_dir = "/tmp/dstack-verifier/cache"
image_download_url = "https://download.dstack.org/os-images/mr_{OS_IMAGE_HASH}.tar.gz"
image_download_timeout_secs = 300
pccs_url = "https://pccs.phala.network"
```

## Usage

### Running with Cargo

```bash
# Run with default config
cargo run --bin dstack-verifier

# Run with custom config file
cargo run --bin dstack-verifier -- --config /path/to/config.toml

# Set via environment variables
DSTACK_VERIFIER_PORT=8080 cargo run --bin dstack-verifier
```

### Running with Docker Compose

```yaml
services:
  dstack-verifier:
    image: dstacktee/dstack-verifier:latest
    ports:
      - "8080:8080"
    restart: unless-stopped
```

Save the docker compose file as `docker-compose.yml` and run `docker compose up -d`.

### Request verification

Grab a quote from your app. It's depends on your app how to grab a quote.

```bash
# Grab a quote from the demo app
curl https://712eab2f507b963e11144ae67218177e93ac2a24-3000.test0.dstack.org:12004/GetQuote?report_data=0x1234 -o quote.json

```

Send the quote to the verifier.

```bash
$ curl -s -d @quote.json localhost:8080/verify | jq
{
  "is_valid": true,
  "details": {
    "quote_verified": true,
    "event_log_verified": true,
    "os_image_hash_verified": true,
    "report_data": "12340000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "tcb_status": "UpToDate",
    "advisory_ids": [],
    "app_info": {
      "app_id": "e631a04a5d068c0e5ffd8ca60d6574ac99a18bda",
      "compose_hash": "e631a04a5d068c0e5ffd8ca60d6574ac99a18bdaf0417d129d0c4ac52244d40f",
      "instance_id": "712eab2f507b963e11144ae67218177e93ac2a24",
      "device_id": "ee218f44a5f0a9c3233f9cc09f0cd41518f376478127feb989d5cf1292c56a01",
      "mrtd": "f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077",
      "rtmr0": "68102e7b524af310f7b7d426ce75481e36c40f5d513a9009c046e9d37e31551f0134d954b496a3357fd61d03f07ffe96",
      "rtmr1": "a7b523278d4f914ee8df0ec80cd1c3d498cbf1152b0c5eaf65bad9425072874a3fcf891e8b01713d3d9937e3e0d26c15",
      "rtmr2": "dbf4924c07f5066f3dc6859844184344306aa3263817153dcaee85af97d23e0c0b96efe0731d8865a8747e51b9e351ac",
      "rtmr3": "5e7d8d84317343d28d73031d0be3c75f25facb1b20c9835a44582b8b0115de1acfe2d19350437dbd63846bcc5d7bf328",
      "mr_system": "145010fa227e6c2537ad957c64e4a8486fcbfd8265ddfb359168b59afcff1d05",
      "mr_aggregated": "52f6d7ccbee1bfa870709e8ff489e016e2e5c25a157b7e22ef1ea68fce763694",
      "os_image_hash": "b6420818b356b198bdd70f076079aa0299a20279b87ab33ada7b2770ef432a5a",
      "key_provider_info": "7b226e616d65223a226b6d73222c226964223a223330353933303133303630373261383634386365336430323031303630383261383634386365336430333031303730333432303030343139623234353764643962386161363434366439383066313336666666373831326563643663373737343065656230653238623130643536633063303030323861356236653539646365613330376435383362643166373037363965396331313664663262636662313735386139356438363133653764653163383438326330227d"
    }
  },
  "reason": null
}
```

## Verification Process

The verifier performs three main verification steps:

1. **Quote Verification**: Validates the TDX quote using dcap-qvl, checking the quote signature and TCB status
2. **Event Log Verification**: Replays event logs to ensure RTMR values match and extracts app information
3. **OS Image Hash Verification**:
   - Automatically downloads OS images if not cached locally
   - Uses dstack-mr to compute expected measurements
   - Compares against the verified measurements from the quote

All three steps must pass for the verification to be considered valid.
