# dstack-verifier

A HTTP server that provides CVM (Confidential Virtual Machine) verification services using the same verification process as the dstack KMS.

## Features

- **TDX Quote Verification**: Uses dcap-qvl to verify TDX quotes
- **Event Log Verification**: Validates event logs and extracts app information
- **OS Image Hash Verification**: Uses dstack-mr to ensure OS image hash matches expected measurements
- **Automatic Image Download**: Downloads and caches OS images automatically when not found locally
- **RESTful API**: Simple HTTP endpoints for verification requests

## API Endpoints

### POST /verify

Verifies a CVM attestation with the provided quote, event log, and VM configuration.

**Request Body:**
```json
{
  "quote": "hex-encoded-quote",
  "event_log": "hex-encoded-event-log",
  "vm_config": "json-vm-config-string",
  "pccs_url": "optional-pccs-url"
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

Configuration can be provided via:
1. TOML file (default: `dstack-verifier.toml`)
2. Environment variables with prefix `DSTACK_VERIFIER_`
3. Command line arguments

### Configuration Options

- `host`: Server bind address (default: "0.0.0.0")
- `port`: Server port (default: 8080)
- `image_cache_dir`: Directory for cached OS images (default: "/tmp/dstack-verifier/cache")
- `image_download_url`: URL template for downloading OS images (default: GitHub releases URL)
- `image_download_timeout_secs`: Download timeout in seconds (default: 300)
- `pccs_url`: Optional PCCS URL for quote verification

### Example Configuration File

```toml
host = "0.0.0.0"
port = 8080
image_cache_dir = "/var/cache/dstack-verifier"
image_download_url = "http://0.0.0.0:8000/mr_{OS_IMAGE_HASH}.tar.gz"
image_download_timeout_secs = 300
pccs_url = "https://pccs.example.com"
```

## Usage

```bash
# Run with default config
cargo run --bin dstack-verifier

# Run with custom config file
cargo run --bin dstack-verifier -- --config /path/to/config.toml

# Set via environment variables
DSTACK_VERIFIER_PORT=9000 cargo run --bin dstack-verifier
```

## Testing

Two test scripts are provided for easy testing:

### Full Test (with server management)
```bash
./test.sh
```
This script will:
- Build the project
- Start the server
- Run the verification test
- Display detailed results
- Clean up automatically

### Quick Test (assumes server is running)
```bash
./quick-test.sh
```
This script assumes the server is already running and just sends a test request.

## Verification Process

The verifier performs three main verification steps:

1. **Quote Verification**: Validates the TDX quote using dcap-qvl, checking the quote signature and TCB status
2. **Event Log Verification**: Replays event logs to ensure RTMR values match and extracts app information
3. **OS Image Hash Verification**:
   - Automatically downloads OS images if not cached locally
   - Uses dstack-mr to compute expected measurements
   - Compares against the verified measurements from the quote

All three steps must pass for the verification to be considered valid.

### Automatic Image Download

When an OS image is not found in the local cache, the verifier will:

1. **Download**: Fetch the image tarball from the configured URL
2. **Extract**: Extract the tarball contents to a temporary directory
3. **Verify**: Check SHA256 checksums to ensure file integrity
4. **Validate**: Confirm the OS image hash matches the computed hash
5. **Cache**: Move the validated files to the cache directory for future use

The download URL template uses `{OS_IMAGE_HASH}` as a placeholder that gets replaced with the actual OS image hash from the verification request.

## Dependencies

- dcap-qvl: TDX quote verification
- dstack-mr: OS image measurement computation
- ra-tls: Attestation handling and verification
- rocket: HTTP server framework