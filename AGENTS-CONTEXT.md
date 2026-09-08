# AGENTS-CONTEXT.md

## Project Overview

`mb64` is a multi-language security library providing:
1. **AES-256-GCM Authenticated Encryption**: Strong encryption with tamper detection (16-byte Poly1305/GHASH Auth Tag).
2. **ChaCha20 ARX Deterministic Base64 Shuffling**: Key-derived permutation of the 64-character Base64 alphabet using ChaCha20 quarter-round operations.
3. **Nonce-Integrated Replay Attack Protection (TTL)**: 4-byte standard UNIX timestamp (`uint32` Big-Endian) embedded directly inside the 12-byte Nonce, enabling sub-minute TTL validation with zero additional payload overhead.

---

## Wire Format & Binary Layout

```text
+-------------------------------------------------------------+
| Intermediate Binary (Before Base64 Shuffling)               |
+------------------------------+---------------+--------------+
| 12-byte Nonce                | N-byte        | 16-byte      |
| [ 4B Unix Timestamp | 8B ]   | Ciphertext    | Auth Tag     |
+------------------------------+---------------+--------------+
                               ▲
                               │ mb64 Custom Base64 Encoding
                               ▼
+-------------------------------------------------------------+
| Final Output: Shuffled Base64 String                        |
| (1-byte plaintext = 29B binary -> 40 chars Base64)          |
+-------------------------------------------------------------+
```

### Key Derivation Rules
- **Base64 Shuffle Seed**: `SHA256(baseKey)`
- **AES-GCM Key**: `SHA256("gcm:" + baseKey)` (Decoupled from calendar dates for stable cross-day decryption)

---

## Decoding & Validation Pipeline

When decoding with TTL (`DecodeWithTTL(data, ttl)`):
1. **Preliminary Timestamp Check (Zero-Alloc, ~11ns)**:
   - Pre-decodes the first 8 Base64 characters into a fixed 6-byte stack buffer.
   - Extracts the 4-byte `uint32` UNIX timestamp.
   - Rejects expired packets (`now - ts > ttl`) or future clock drift (`now - ts < -60s`) **before** allocating memory or running AES decryption.
2. **Full Decode & Decryption**:
   - Decodes complete Base64 payload.
   - Executes `gcm.Open(nil, nonce, ciphertext, nil)`. Any tamper with ciphertext or Nonce (including timestamp) causes authentication failure.

---

## Codebase Map & Implementations

| Path | Purpose / Description | Key APIs / Entrypoints |
| :--- | :--- | :--- |
| `mb64.go` | Core Go implementation | `SetEncoding`, `Encode`, `Decode`, `DecodeWithTTL`, `EncodeWithTime`, `Bypass` |
| `mb64_test.go` | Full Go test suite (Continuity, ARX, TTL, Boundaries) | `go test -v ./...` |
| `cmd/mb64/main.go` | CLI tool | `mb64 --key <k> [--ttl <dur>] [encrypt\|decrypt]` |
| `cmd/mb64c/mb64_c.go` | C shared library exports | `SetEncodingC`, `EncodeC`, `DecodeC`, `DecodeWithTTLC`, `FreeC` |
| `internal/wasm/wasm.go` | WebAssembly bindings | `mb64.setFont`, `mb64.renderIn`, `mb64.renderOut(data, ttlSeconds)` |
| `alternatives/js/mb64.js` | Pure JavaScript (Node/Browser) implementation | `SetEncoding`, `Encode`, `Decode`, `DecodeWithTTL`, `EncodeWithTime` |
| `alternatives/js/test/` | JavaScript test suite & Go-JS cross-language tests | `cd alternatives/js && bash run-test.sh` |
| `shared-object/` | C shared object wrappers (Python, Node koffi) | `shared-object/javascript/`, `shared-object/python/` |

---

## Build & Test Commands

```bash
# 1. Run all Go tests
go test -v ./...

# 2. Run JavaScript and cross-language integration tests
cd alternatives/js && bash run-test.sh

# 3. Build Go CLI binary
./build-mb64.sh

# 4. Build C Shared Library (.so / .dylib)
./build-libmb64.sh

# 5. Build WebAssembly bundle
./build-wasm.sh
```

---

## Critical Maintenance Invariants for AI Agents

1. **Protocol Synchronization**: Any changes to Nonce structure, timestamp encoding, or key derivation in `mb64.go` **must** be mirrored across:
   - `alternatives/js/mb64.js`
   - `cmd/mb64c/mb64_c.go`
   - `internal/wasm/wasm.go`
2. **Date Decoupling**: Do NOT add calendar date strings (`YYYYMMDD`) to `generateKeyGCM`. Timestamps inside Nonce handle expiration; encryption keys must remain deterministic across day boundaries.
3. **Header Length**: Minimum valid ciphertext requires at least 8 Base64 characters to decode the 4-byte timestamp header (Nonce 12B + Tag 16B = 28B minimum payload).
