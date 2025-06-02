#!/bin/bash

echo "Starting all SGX services using docker-compose..."
docker compose up --build -d

echo "=========================="
echo "Services started!"
echo "=========================="
echo "Key provider endpoint: https://localhost:3443"
echo "  - Using shared socket with AESM service"
echo "  - Socket location: /var/run/aesmd/aesm.socket"
echo 
echo "Check logs with:"
echo "  docker compose logs -f aesmd"
echo "  docker compose logs -f gramine-sealing-key-provider"
echo "==========================" 