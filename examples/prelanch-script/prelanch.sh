# This is an example of how to write a pre-launch script of DStack App Compose.

# The script is run in /tapp directory. The app-compose.json file is in the same directory.

set -e

# We fully handle the docker compose logic in this script.
echo "Extracting docker compose file"
jq -j '.docker_compose_file' app-compose.json >docker-compose.yaml
echo "Removing orphans"
tdxctl remove-orphans -f docker-compose.yaml || true
echo "Restarting docker"
chmod +x /usr/bin/containerd-shim-runc-v2
systemctl restart docker

# Use a container to setup the environment
echo "Setting up the environment"
tdxctl notify-host -e "boot.progress" -d "setting up the environment" || true
docker run \
    --rm \
    --name dstack-app-setup \
    -v /tapp:/tapp \
    -w /tapp \
    -v /var/run/docker.sock:/var/run/docker.sock \
    curlimages/curl:latest \
    -s https://raw.githubusercontent.com/Dstack-TEE/meta-dstack/refs/heads/main/meta-dstack/recipes-core/base-files/files/motd -o /tapp/motd

echo "Starting containers"
tdxctl notify-host -e "boot.progress" -d "starting containers" || true
if ! docker compose up -d; then
    tdxctl notify-host -e "boot.error" -d "failed to start containers"
    exit 1
fi

# Use exit to skip the original docker compose handling
exit 0
