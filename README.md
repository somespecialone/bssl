# BSSL

[![Made in Ukraine](https://img.shields.io/badge/made_in-ukraine-ffd700.svg?labelColor=0057b7)](https://stand-with-ukraine.pp.ua)
[![license](https://img.shields.io/github/license/somespecialone/bssl)](https://github.com/somespecialone/bssl/blob/main/LICENSE)
[![pypi](https://img.shields.io/pypi/v/bssl)](https://pypi.org/project/bssl)
[![python versions](https://img.shields.io/pypi/pyversions/bssl)](https://pypi.org/project/bssl)
[![CI](https://github.com/somespecialone/bssl/actions/workflows/ci.yml/badge.svg)](https://github.com/somespecialone/bssl/actions/workflows/ci.yml)

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

## Integrations and usage examples

See [bssl-integrations](https://github.com/somespecialone/bssl-integrations) repo.

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

[//]: # (TODO ubuntu build instruments example)

## Credits

* [cloudflare/boring](https://github.com/cloudflare/boring)
* [0x676e67/boring2](https://github.com/0x676e67/boring2)
* [0x676e67/wreq](https://github.com/0x676e67/wreq) - certificate compressors code
* [0x676e67/rnet](https://github.com/0x676e67/rnet) - building reference
