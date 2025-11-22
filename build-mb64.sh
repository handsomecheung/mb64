#!/bin/bash
set -e


cd "$(dirname "${BASH_SOURCE[0]}")"

mkdir -p build
go build -o build/mb64 ./cmd/mb64
