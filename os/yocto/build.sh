#!/bin/bash
SCRIPT_DIR=$(
    cd $(dirname $0)
    pwd
)
ACTION=$1

META_DIR=$SCRIPT_DIR
DSTACK_DIR=$SCRIPT_DIR/dstack
CERTS_DIR=$(pwd)/certs
IMAGES_DIR=$(pwd)/images
RUN_DIR=$(pwd)/run
RUST_BUILD_DIR=$(pwd)/rust-target
CERBOT_WORKDIR=$RUN_DIR/certbot
KMS_UPGRADE_REGISTRY_DIR=$RUN_DIR/kms/upgrade_registry
KMS_CERT_LOG_DIR=$RUN_DIR/kms/cert_log/

GATEWAY_CERT=${GATEWAY_CERT:-$CERTS_DIR/live/cert.pem}
GATEWAY_KEY=${GATEWAY_KEY:-$CERTS_DIR/live/key.pem}

CONFIG_FILE=./build-config.sh

check_config() {
    local template_file=$1
    local config_file=$2

    # extract all variables in template file
    local variables=$(grep -oE '^\s*[A-Z_]+=' $template_file | sort)

    # check if each variable is set in config file
    local var missing=0
    for var in $variables; do
        if ! grep -qE "^\s*$var" $config_file; then
            echo "Variable $var is not set in $config_file"
            missing=1
        fi
    done
    if [ $missing -ne 0 ]; then
        return 1
    fi
    return 0
}

require_config() {

    # Base port for RPC services
    BASE_PORT=$(($RANDOM % 1000 * 10 + 10000))
    CID_POOL_START=$(($RANDOM % 1000 * 1000 + 20000))
    SUBNET_INDEX=$(($RANDOM % 240 + 10))

    cat <<EOF >build-config.sh.tpl
# DNS domain of kms rpc and dstack-gateway rpc
# *.1022.dstack.org resolves to 10.0.2.2 which is the IP of the host system
# from CVMs point of view
KMS_DOMAIN=kms.1022.dstack.org
GATEWAY_DOMAIN=gateway.1022.dstack.org

# CIDs allocated to VMs start from this number of type unsigned int32
VMM_CID_POOL_START=$CID_POOL_START
# CID pool size
VMM_CID_POOL_SIZE=1000

VMM_RPC_LISTEN_PORT=$BASE_PORT
# Whether port mapping from host to CVM is allowed
VMM_PORT_MAPPING_ENABLED=true
# Host API configuration, type of uint32
VMM_VSOCK_LISTEN_PORT=$BASE_PORT
# Whether to enable GPU support
VMM_ENABLE_GPU=false

KMS_RPC_LISTEN_PORT=$(($BASE_PORT + 1))
GATEWAY_RPC_LISTEN_PORT=$(($BASE_PORT + 2))

GATEWAY_WG_INTERFACE=dgw-$USER
GATEWAY_WG_LISTEN_PORT=$(($BASE_PORT + 3))
GATEWAY_WG_IP=10.$SUBNET_INDEX.3.1
GATEWAY_SERVE_PORT=$(($BASE_PORT + 4))
GATEWAY_CERT=$CERBOT_WORKDIR/live/cert.pem
GATEWAY_KEY=$CERBOT_WORKDIR/live/key.pem

BIND_PUBLIC_IP=0.0.0.0

GATEWAY_PUBLIC_DOMAIN=<your domain for zt-https>

# for certbot
CERTBOT_ENABLED=false
CF_API_TOKEN=
ACME_URL=https://acme-staging-v02.api.letsencrypt.org/directory
EOF
    if [ -f $CONFIG_FILE ]; then
        source $CONFIG_FILE
        # check if any variable in build-config.sh.tpl is not set in build-config.sh.
        # This might occur if the build-config.sh is generated from and old repo.
        check_config build-config.sh.tpl $CONFIG_FILE
        if [ $? -ne 0 ]; then
            exit 1
        fi
        rm -f build-config.sh.tpl

        if [ -z "$GATEWAY_SERVE_PORT" ]; then
            GATEWAY_SERVE_PORT=${GATEWAY_LISTEN_PORT1}
        fi
        AGENT_PORT=8090
    else
        mv build-config.sh.tpl $CONFIG_FILE
        echo "Config file $CONFIG_FILE created, please edit it to configure the build"
        exit 1
    fi
}

# Step 1: build binaries
build_host() {
    echo "Building binaries"
    (cd $DSTACK_DIR && cargo build --release --target-dir ${RUST_BUILD_DIR})
    for bin in dstack-gateway dstack-kms dstack-vmm supervisor; do
        cp "${RUST_BUILD_DIR}/release/${bin}" ".${bin}.new"
        mv -f ".${bin}.new" "./${bin}"
    done
}

# Step 2: build guest images
build_guest() {
    echo "Building guest images"
    if [ -z "$BBPATH" ]; then
        source $SCRIPT_DIR/dev-setup $1
    fi
    make -C $META_DIR dist DIST_DIR=$IMAGES_DIR BB_BUILD_DIR=${BBPATH}
}

# Step 4: generate config files

build_cfg() {
    echo "Building config files"
    if [ -f "gateway.toml" ]; then
        echo "Reading existing WireGuard key from gateway.toml"
        GATEWAY_WG_KEY=$(awk '
            /^\s*private_key\s*=/ {
                # Remove leading whitespace and "private_key ="
                gsub(/^\s*private_key\s*=\s*/, "")
                # Remove quotes (both single and double)
                gsub(/^["'"'"']|["'"'"']$/, "")
                # Remove trailing whitespace and comments
                gsub(/\s*(#.*)?$/, "")
                if (length($0) > 0) {
                    print $0
                    exit
                }
            }
        ' gateway.toml)

        if [ -z "$GATEWAY_WG_KEY" ]; then
            echo "Error: Could not read WireGuard key from existing gateway.toml"
            exit 1
        fi
    else
        echo "Generating new WireGuard key"
        GATEWAY_WG_KEY=$(wg genkey)
    fi

    GATEWAY_WG_PUBKEY=$(echo $GATEWAY_WG_KEY | wg pubkey)
    # kms
    cat <<EOF >kms.toml
log_level = "info"

[rpc]
address = "127.0.0.1"
port = $KMS_RPC_LISTEN_PORT

[rpc.tls]
key = "$CERTS_DIR/rpc.key"
certs = "$CERTS_DIR/rpc.crt"

[rpc.tls.mutual]
ca_certs = "$CERTS_DIR/tmp-ca.crt"
mandatory = false

[core]
cert_dir = "$CERTS_DIR"

[core.gpu]
enabled = $VMM_ENABLE_GPU

[core.auth_api]
type = "dev"

[core.onboard]
quote_enabled = false
address = "127.0.0.1"
port = $KMS_RPC_LISTEN_PORT
auto_bootstrap_domain = "$KMS_DOMAIN"

[core.image]
verify = false
EOF

    # dstack-gateway
    cat <<EOF >gateway.toml
log_level = "info"
address = "127.0.0.1"
port = $GATEWAY_RPC_LISTEN_PORT

[tls]
key = "$CERTS_DIR/gateway-rpc.key"
certs = "$CERTS_DIR/gateway-rpc.cert"

[tls.mutual]
ca_certs = "$CERTS_DIR/gateway-ca.cert"
mandatory = false

[core]
kms_url = "https://localhost:$KMS_RPC_LISTEN_PORT"
rpc_domain = "$GATEWAY_DOMAIN"
run_in_dstack = false

[core.sync]
enabled = false

[core.certbot]
enabled = $CERTBOT_ENABLED
# Path to the working directory
workdir = "$CERBOT_WORKDIR"
# ACME server URL
acme_url = "$ACME_URL"
# Cloudflare API token
cf_api_token = "$CF_API_TOKEN"
# Auto set CAA record
auto_set_caa = true
# Domain to issue certificates for
domain = "*.$GATEWAY_PUBLIC_DOMAIN"
# Check renewal interval
renew_interval = "30m"
# Number of days before expiration to trigger renewal
renew_days_before = "10d"
# Renew timeout
renew_timeout = "10m"

[core.wg]
private_key = "$GATEWAY_WG_KEY"
public_key = "$GATEWAY_WG_PUBKEY"
listen_port = $GATEWAY_WG_LISTEN_PORT
ip = "$GATEWAY_WG_IP/24"
reserved_net = ["$GATEWAY_WG_IP/31"]
client_ip_range = "$GATEWAY_WG_IP/24"
config_path = "$RUN_DIR/wg.conf"
interface = "$GATEWAY_WG_INTERFACE"
endpoint = "10.0.2.2:$GATEWAY_WG_LISTEN_PORT"

[core.proxy]
cert_chain = "$GATEWAY_CERT"
cert_key = "$GATEWAY_KEY"
base_domain = "$GATEWAY_PUBLIC_DOMAIN"
listen_addr = "$BIND_PUBLIC_IP"
listen_port = $GATEWAY_SERVE_PORT
agent_port = $AGENT_PORT
app_address_ns_prefix = "_tapp-address"
EOF

    # dstack-vmm config
    cat <<EOF >vmm.toml
log_level = "info"
address = "127.0.0.1"
port = $VMM_RPC_LISTEN_PORT
image_path = "$IMAGES_DIR"
run_path = "$RUN_DIR/vm"
kms_url = "https://localhost:$KMS_RPC_LISTEN_PORT"

[cvm]
kms_urls = ["https://$KMS_DOMAIN:$KMS_RPC_LISTEN_PORT"]
gateway_urls = ["https://$GATEWAY_DOMAIN:$GATEWAY_RPC_LISTEN_PORT"]
cid_start = $VMM_CID_POOL_START
cid_pool_size = $VMM_CID_POOL_SIZE
[cvm.port_mapping]
enabled = $VMM_PORT_MAPPING_ENABLED
address = "127.0.0.1"
range = [
    { protocol = "tcp", from = 1, to = 20000 },
    { protocol = "udp", from = 1, to = 20000 },
]

[gateway]
base_domain = "$GATEWAY_PUBLIC_DOMAIN"
port = $GATEWAY_SERVE_PORT
agent_port = $AGENT_PORT

[host_api]
port = $VMM_VSOCK_LISTEN_PORT
EOF

    mkdir -p $RUN_DIR
    mkdir -p $CERBOT_WORKDIR/backup/preinstalled
}

download_image() {
    local VERSION=""
    local IS_DEV=""

    # Parse arguments to support both formats
    if [[ "$1" == "-dev" ]]; then
        IS_DEV=1
        VERSION=$2
    else
        VERSION=$1
    fi

    echo "Downloading image $VERSION${IS_DEV:+ (dev)}"

    TAG=v$VERSION
    if [ x"$IS_DEV" = x"1" ]; then
        BASENAME=dstack-cloud-dev-$VERSION
    else
        BASENAME=dstack-cloud-$VERSION
    fi
    URL=https://github.com/Dstack-TEE/meta-dstack/releases/download/$TAG/$BASENAME.tar.gz
    if [ -d $IMAGES_DIR/$BASENAME ]; then
        echo "Image already exists"
    else
        mkdir -p $IMAGES_DIR/$BASENAME.tmp
        curl -L $URL -o $IMAGES_DIR/$BASENAME.tar.gz
        tar -xvf $IMAGES_DIR/$BASENAME.tar.gz -C $IMAGES_DIR/$BASENAME.tmp
        rm -f $IMAGES_DIR/$BASENAME.tar.gz
        if [ -d $IMAGES_DIR/$BASENAME.tmp/$BASENAME ]; then
            mv $IMAGES_DIR/$BASENAME.tmp/$BASENAME $IMAGES_DIR/$BASENAME
            rm -rf $IMAGES_DIR/$BASENAME.tmp
        else
            mv $IMAGES_DIR/$BASENAME.tmp $IMAGES_DIR/$BASENAME
        fi
    fi
}

usage() {
    cat <<EOF
Usage: ${0##*/} <action> [args]

Actions:
  host     - Build host binaries only
  guest    - Build guest images only
  cfg      - Generate configuration files only
  dl       - Download a specific image
  hostcfg  - Build host binaries and generate configuration files
  all      - Build everything (host, guest, and configuration)
  help     - Show this help

Build a specific guest flavor (default builds production): set the FLAVORS env var.
  flavor      -> output image
  prod        -> dstack
  dev         -> dstack-dev

  Examples:
    ./build.sh guest                     # build dstack (default)
    FLAVORS=dev ./build.sh guest         # build only dstack-dev
    FLAVORS="prod dev" ./build.sh guest  # build both flavors
EOF
}

case $ACTION in
host)
    build_host
    ;;
guest)
    build_guest $2
    ;;
cfg)
    require_config
    build_cfg
    ;;
dl)
    download_image $2 $3
    ;;
hostcfg)
    require_config
    build_host
    build_cfg
    ;;
all)
    require_config
    build_host
    build_guest
    build_cfg
    ;;
help|-h|--help)
    usage
    ;;
*)
    [ -n "$ACTION" ] && echo "Invalid action: $ACTION" >&2
    usage
    exit 1
    ;;
esac
