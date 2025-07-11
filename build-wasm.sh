#!/bin/bash
set -e

cd "$(dirname "${BASH_SOURCE[0]}")"

mkdir -p build
GOOS=js GOARCH=wasm go build -tags js,wasm -o build/mb64.wasm ./cmd/mb64wasm
