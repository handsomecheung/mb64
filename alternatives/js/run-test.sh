#!/bin/bash
set -e

cd "$(dirname "${BASH_SOURCE[0]}")"

node test/mb64.test.js
node test/shuffle.test.js
node test/mb64.test.integration.js
