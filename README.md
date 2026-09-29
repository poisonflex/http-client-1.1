# HTTP Client 1.1

A from-scratch HTTP/1.1 client written in C.

This is not a library. It is not production software. It is a browser's network layer, built line by line against raw syscalls and OpenSSL — TCP connect, TLS handshake, header parsing, chunked framing, gzip/brotli decoding, cookies, redirects, connection reuse. No HTTP library is used.

> **Status:** Active development. Windows only. Do not use this for anything real.

---

## Features

- **GET / POST** with custom method, headers, and body
- **TLS 1.2 / 1.3** via OpenSSL, with real certificate verification against a CA bundle
- **gzip** and **brotli** response decoding, streaming — no whole-body buffering
- **All three HTTP body framings:** `Content-Length`, `Transfer-Encoding: chunked`, and close-delimited
- **Redirects:** 301, 302, 303, 307, 308, with correct method downgrade (301/302/303 turn POST into GET; 307/308 preserve method and body)
- **Relative redirect resolution** per RFC 3986 §5.2.4
- **Cookies:** capture, persist to disk, domain matching, `Secure` enforcement, `Expires` / `Max-Age` parsing (standard and Google's dash-separated variant)
- **Connection reuse** — HTTP keep-alive with `SO_RCVTIMEO`
- **CLI:** `-o`, `-X`, `-d`, `--port`, `--plain`, `--debug`, `-h`

## Not implemented

- HTTP/2, ALPN
- IPv6
- Chunked request bodies
- Full cookie path scoping (`Secure`, `HttpOnly`, `Path` are partially honored)
- Header folding, trailers, `Location: ?query`
- Configurable timeouts
- Tests

---

## Requirements

**Windows only.** Built and tested on Windows with MSYS2 (MINGW64).

You need:

- **MSYS2** — https://www.msys2.org/
- **gcc**, **OpenSSL 3.x**, **zlib**, **brotli**, **CA certificates** — all installable via `pacman`

### Install the toolchain

Open the **MSYS2 MINGW64** shell (not the plain MSYS2 shell) and run:

```sh
pacman -S mingw-w64-x86_64-gcc \
          mingw-w64-x86_64-openssl \
          mingw-w64-x86_64-zlib \
          mingw-w64-x86_64-brotli \
          mingw-w64-x86_64-ca-certificates
```

This gives you `gcc`, the OpenSSL headers and libraries, zlib, brotli, and the CA bundle at `/mingw64/etc/ssl/certs/ca-bundle.crt`.

---

## Build

From the project directory, in the MSYS2 MINGW64 shell:

```sh
gcc -Wall -Wextra -o http_client.exe http_client.c \
    -lssl -lcrypto -lz -lbrotlidec -lbrotlicommon -lws2_32
```

That produces `http_client.exe`.

### DLLs — required at runtime

The `http_client.exe` links dynamically against several DLLs. On Windows, `C:\Windows\System32\libcrypto-3-x64.dll` (if it exists) **shadows** the mingw64 one and will cause a load failure or crash. Copy the correct DLLs next to `http_client.exe`:

```
libssl-3-x64.dll
libcrypto-3-x64.dll
libbrotlidec.dll
libbrotlicommon.dll
zlib1.dll
```

They live in `C:\msys64\mingw64\bin\` on a standard MSYS2 install. Copy them into the same directory as `http_client.exe`.

You can verify which DLLs an exe needs with:

```sh
ldd http_client.exe
```

If `ldd` shows a `libcrypto` from `C:\Windows\System32`, that is the wrong one — copy the mingw64 version next to the exe.

---

## Run

```sh
MSYS2_ARG_CONV_EXCL="*" ./http_client.exe <host> <path> [flags]
```

**The `MSYS2_ARG_CONV_EXCL="*"` prefix is required.** MSYS2 rewrites `/`-prefixed arguments into Windows paths by default. Without this environment variable, a path argument like `/index.html` becomes `C:/msys64/index.html`, the server receives garbage, and you get a `400 Bad Request`. Every run in this README includes the prefix.

### Flags

| Flag | Meaning |
|---|---|
| `-o <file>` | Output file. `-` means stdout. Default: `decoded_body.html` |
| `-X <method>` | HTTP method. Default: `GET`, or `POST` if `-d` is given |
| `-d <body>` | Request body. Implies `POST` unless `-X` overrides |
| `--port <n>` | Port. Default: `443` (TLS), or `80` with `--plain` |
| `--plain` | Plain TCP — no TLS |
| `--debug` | Print the raw request bytes to stderr |
| `-h`, `--help` | Print usage |

### Examples

```sh
# GET, TLS, body printed to stdout
MSYS2_ARG_CONV_EXCL="*" ./http_client.exe example.com / -o -

# GET, TLS, body written to a file
MSYS2_ARG_CONV_EXCL="*" ./http_client.exe example.com / -o page.html

# POST with a JSON body
MSYS2_ARG_CONV_EXCL="*" ./http_client.exe httpbin.org /post -d '{"hello":"world"}'

# Plain HTTP on port 80
MSYS2_ARG_CONV_EXCL="*" ./http_client.exe example.com / --plain --port 80

# Inspect the exact request bytes sent
MSYS2_ARG_CONV_EXCL="*" ./http_client.exe example.com / --debug 2>req.txt
```

### What to expect on a normal run

For `example.com /`:

```
Using CA bundle: ca-bundle.crt
TLS TLSv1.3, cipher TLS_AES_256_GCM_SHA384, cert CN=/CN=example.com
Sent 113 bytes

HTTP/1.1 200 OK
Date: ...
Content-Type: text/html; charset=utf-8
Transfer-Encoding: chunked
Connection: keep-alive
Content-Encoding: br
...
Status_code = 200
content_length = -1
content_encoding = "br"

brotli decode enabled
Streamed 409 bytes (chunked) to -
```

The decoded body is written to the file given by `-o` (or stdout with `-o -`). Everything above the `Status_code` line is the raw response header block, echoed for inspection.

---

## Notes on the CA bundle

On startup the client searches for a CA bundle in this order:

1. `SSL_CERT_FILE` environment variable, if set
2. `ca-bundle.crt` next to `http_client.exe`
3. `C:/msys64/mingw64/etc/ssl/certs/ca-bundle.crt`
4. `C:/msys64/mingw64/ssl/certs/ca-bundle.crt`
5. `C:/Program Files/Git/mingw64/etc/ssl/certs/ca-bundle.crt`
6. `C:/Program Files/Git/mingw64/ssl/certs/ca-bundle.crt`

The first path that loads wins. If none loads, the client exits — it does **not** fall back to skipping certificate verification.

The bundled `ca-bundle.crt` in this repository comes from the MSYS2 `ca-certificates` package and is included so the client runs out of the box.

---

## License

MIT. See `LICENSE`.
