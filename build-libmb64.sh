#!/bin/bash
set -e


cd "$(dirname "${BASH_SOURCE[0]}")"

mkdir -p build
go build -buildmode=c-shared -o build/libmb64.so cmd/mb64c/mb64_c.go
