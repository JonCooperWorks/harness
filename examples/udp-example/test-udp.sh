#!/bin/bash

# Test script for UDP example plugin
# Sends a UDP datagram to localhost:6000

set -e

cd "$(dirname "$0")"

echo "Building UDP example plugin..."
cargo build --target wasm32-wasip1 --release

echo ""
echo "Testing UDP plugin..."
echo "Sending UDP datagram to localhost:6000"
echo ""

go run test-udp.go

