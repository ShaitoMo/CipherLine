# Secure TCP Chat (C++ Server / Go Client)

## Overview
- TCP client–server chat system  
- Secure session established using a key-exchange handshake  
- All messages encrypted with **AES-GCM**  
- Server supports multiple clients (multi-threaded)

---

## Requirements
- Windows 10 / 11
- **Server:** MinGW g++ + OpenSSL dev libs (build from source — see below)
- **Client:** Go (installed and in PATH)

---

## Pre-Shared Key (PSK) Setup

The handshake is authenticated with a shared secret so an on-path attacker
can't silently proxy the connection (MITM). Both the server and the client
must be started with the **same** key in the `CHAT_PSK` environment
variable — a 64-character hex string (32 bytes). It is no longer hardcoded
in source.

Generate one:
```bash
openssl rand -hex 32
```

Set it before running either side:

**PowerShell**
```powershell
$env:CHAT_PSK = "<64 hex chars>"
```

**CMD**
```bat
set CHAT_PSK=<64 hex chars>
```

If `CHAT_PSK` is missing or not valid 64-character hex, the server/client
refuses to start.

---

## Run Server

Build it first (see "Build Server" below), then:

### CMD
```bat
server.exe 127.0.0.1 9000
```

### PowerShell

```powershell
.\server.exe 127.0.0.1 9000
```

Expected output:

```
[*] Listening on 127.0.0.1:9000
```

> Do **not** double-click `server.exe` (it requires arguments).

---

## Run Client (Go)

Run in **CMD or PowerShell** (from the client folder):

```bash
go run client.go netio.go
```

Connect to the server:

```
/connect 127.0.0.1 9000
```

---

## Client Commands

* `/connect <ip> <port>` – start secure session
* `/reconnect` – reconnect to last server
* `/close` – close current session
* `/quit` – exit client
* `<text>` – send encrypted message

---

## Build Server

No prebuilt binary is shipped — build it from `server/` with either:

```bash
make
```

or, if you don't have `make` (PowerShell, from `server/`):

```powershell
.\build.ps1
```

Both just wrap:
```bash
g++ -std=c++17 -O2 -Wall -Wextra server.cpp net_io.cpp -o server.exe -lws2_32 -lssl -lcrypto
```

### If build fails

* `g++ not recognized` → MinGW not installed or not in PATH
* `cannot find -lssl / -lcrypto` → OpenSSL not installed

**MSYS2:**

```bash
pacman -S mingw-w64-x86_64-openssl
```

---

## Testing

`client/integration_test.go` builds the real C++ server and drives it with
the Go client's own handshake/frame code, verifying the two independent
implementations actually interoperate (not just that each compiles).

```bash
cd client
go test -v ./...
```

Requires `g++`/OpenSSL on `PATH` to build the server; the test skips itself
(rather than failing) if the toolchain isn't available.

---

## Notes

* VS Code works because it provides required DLLs in PATH.
* If the server closes immediately, it was started without arguments.
* When running on another PC, required DLLs must be in the same folder as `server.exe`.

---

## Threat Model

**Protects against:**
* Passive eavesdropping on the wire — every frame is AES-256-GCM encrypted.
* An active man-in-the-middle without the PSK — the handshake transcript
  (both parties' ephemeral X25519 public keys + nonces) is HMAC-SHA256
  authenticated with the PSK, so a forged ServerHello/ClientAuth fails
  verification and the handshake aborts.
* Message tampering within a session — GCM's authentication tag detects any
  modification to ciphertext or nonce.

**Does NOT protect against:**
* Compromise of the PSK itself — anyone holding `CHAT_PSK` can pass the
  handshake and MITM future sessions. (Past captured sessions stay safe even
  if the PSK later leaks: the PSK only authenticates the handshake, it never
  feeds into session-key derivation, which comes from the ephemeral X25519
  exchange — see `derive_session_key` / `deriveSessionKey`.)
* Client identity — every client authenticates with the same shared PSK, so
  the server has no cryptographic way to distinguish one client from
  another (only IP:port in logs).
* Denial-of-service — the server caps total concurrent connections
  (currently 100, see `MAX_CONNECTIONS` in `server.cpp`) but has no per-IP
  rate limiting, so a single source can still consume the whole cap.
