# BSSL

[![Made in Ukraine](https://img.shields.io/badge/made_in-ukraine-ffd700.svg?labelColor=0057b7)](https://stand-with-ukraine.pp.ua)
[![license](https://img.shields.io/github/license/somespecialone/bssl)](https://github.com/somespecialone/bssl/blob/main/LICENSE)
[![pypi](https://img.shields.io/pypi/v/bssl)](https://pypi.org/project/bssl)
[![python versions](https://img.shields.io/pypi/pyversions/bssl)](https://pypi.org/project/bssl)
[![CI](https://github.com/somespecialone/bssl/actions/workflows/ci.yml/badge.svg)](https://github.com/somespecialone/bssl/actions/workflows/ci.yml)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/somespecialone/bssl)

Modern and flexible TLS for Python, built on **BoringSSL**

> This project is an early attempt to implement the idea of [PEP-748](https://peps.python.org/pep-0748/) in practice,
> with main goal is to provide a clean, extensible, and flexible alternative to Python’s built-in `ssl` module

## Learning resources

* 🐍 [Python API source code](./bssl)
* 📖 [DeepWiki](https://deepwiki.com/somespecialone/bssl)
* 📑 [PEP-748](https://peps.python.org/pep-0748/)
* [Integrations](https://github.com/somespecialone/bssl-integrations)

## Supported platforms

- **Linux** (glibc/musl):
    - x86_64
    - x86 (i686)
    - aarch64
    - armv7

- **Windows**:
    - x86_64
    - x86 (i686)
    - aarch64

- **macOS**:
    - x86_64
    - aarch64 (Apple Silicon)

## Installation

While project listed on [PyPI](https://pypi.org/project/bssl) it is in _prerelease_ state,
so consider allowing _prereleases_ during installation:

```sh
pip install --pre bssl
poetry add --allow-prereleases bssl
uv add --prerelease if-necessary bssl  # optional as uv must allow prereleases by default for prerelease-only packages
```

## Usage

Quick overview of core functionality usage

### TLS configuration and context

Creating TLS client context from configuration

```py
from bssl import *

# Google Chrome v133 TLS options with turned off HTTP/2 for simplicity
config = TLSClientConfiguration(
    curves=[Curves.X25519MLKEM768, Curves.X25519, Curves.P_256, Curves.P_384],
    ciphers=[
        CipherSuite.TLS_AES_128_GCM_SHA256,
        CipherSuite.TLS_AES_256_GCM_SHA384,
        CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
    ],
    sigalgs=[
        SignatureAlgorithms.ecdsa_secp256r1_sha256,
        SignatureAlgorithms.rsa_pss_rsae_sha256,
        SignatureAlgorithms.rsa_pkcs1_sha256,
        SignatureAlgorithms.ecdsa_secp384r1_sha384,
        SignatureAlgorithms.rsa_pkcs1_sha384,
        SignatureAlgorithms.rsa_pkcs1_sha512,
    ],
    certificate_compression_algorithms=[CertificateCompressionAlgorithm.BROTLI],
    alps_protocols=[NextProtocol.HTTP1],
    inner_protocols=[NextProtocol.HTTP1],
    alps_use_new_codepoint=True,
    ech_grease=False,
    permute_extensions=True,
    grease=True,
    ocsp_stapling=True,
    signed_cert_timestamps=True,
    lowest_supported_version=TLSVersion.TLSv1_2,
    highest_supported_version=TLSVersion.TLSv1_3,
)

# Create TLS client context from configuration
ctx = ClientContext(config)
```

### TLSSocket

Establishing a sync socket network TLS connection

```py
# Establish sync socket connection
sock = ctx.connect(("www.google.com", 443))

# Send HTTP request
sock.send(b"GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n")

# Receive response
resp = sock.recv(4096)
print(resp)

# Clean up
sock.close(True)
```

### TLSBuffer

Creating a memory-based TLS buffer separated from network I/O operations.
Handling `WantReadError` and `WantWriteError` exceptions logic are omitted for simplicity.

```py
# Create buffer for hostname
buffer = ctx.create_buffer("www.google.com")

# Perform handshake (generates outgoing handshake data)
buffer.do_handshake()

# Read data that needs to be sent to server
outgoing = buffer.process_outgoing()

# Send outgoing data via your transport layer

# Writing received data from server via your transport layer
incoming = b"example of encrypted data from server"
buffer.process_incoming(incoming)

# Write application data (encrypts it)
buffer.write(b"GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n")

# Read encrypted data to send
outgoing = buffer.process_outgoing()

# Send outgoing data via your transport layer

# Writing received data from server via your transport layer
incoming = b"example of encrypted data from server"
buffer.process_incoming(incoming)

resp = buffer.read(4096)
print(resp)

# Clean up
buffer.shutdown()

# Read shutdown data
outgoing = buffer.process_outgoing()

# Send outgoing data via your transport layer
```

### Integrations

For integration with existing http clients, take a look at
[bssl-integrations](https://github.com/somespecialone/bssl-integrations) repo.

## Building

Package is built using [maturin](https://github.com/PyO3/maturin).

Refer to [boring crate ci](https://github.com/cloudflare/boring/blob/master/.github/workflows/ci.yml) and
[BoringSSL build docs](https://github.com/google/boringssl/blob/main/BUILDING.md) to build `boring` crate.

You can look at [project ci](./.github/workflows/ci.yml) build steps and
🐋 [Docker image for musl cross-building](https://github.com/somespecialone/rust-musl-cross-gcc)
to see how it is done.

### Development

1) Ensure build dependencies from above are installed
2) Create and activate a `Python` virtual environment by _your_ choice
3) Install project in editable mode with:
   ```sh
   maturin develop
   ```

For example, on `Windows` you may need `Perl`, `CMake`, and `LLVM`.

For `Ubuntu` or `Debian`: `build-essential`, `cmake`, `perl`, `pkg-config` and `libclang-dev`

## Credits

* [cloudflare/boring](https://github.com/cloudflare/boring)
* [0x676e67/boring2](https://github.com/0x676e67/boring2)
* [0x676e67/wreq](https://github.com/0x676e67/wreq) - certificate compressors code
* [0x676e67/rnet](https://github.com/0x676e67/rnet) - building reference
* [tls.peet.ws](https://tls.peet.ws/) - TLS fingerprinting API
* [bssl-integrations](https://github.com/somespecialone/bssl-integrations) - integrations with popular libraries
