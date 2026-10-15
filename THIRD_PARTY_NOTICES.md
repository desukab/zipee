# Third-party notices

Every direct and transitive dependency of Zipee with the licence each offers.
Generated from `cargo metadata` during the release audit.

## Summary

| Licence | Crates |
|---|---|
| `MIT OR Apache-2.0` | 68 |
| `Apache-2.0 OR MIT` | 6 |
| `MIT` | 5 |
| `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | 4 |
| `BSD-3-Clause` | 3 |
| `Apache-2.0` | 3 |
| `MIT/Apache-2.0` | 2 |
| `MIT OR Apache-2.0 OR LGPL-2.1-or-later` | 2 |
| `0BSD OR MIT OR Apache-2.0` | 1 |
| `CC0-1.0 OR MIT-0 OR Apache-2.0` | 1 |
| `Unlicense OR MIT` | 1 |
| `MIT OR Zlib OR Apache-2.0` | 1 |
| `(MIT OR Apache-2.0) AND Unicode-3.0` | 1 |

## Copyleft audit

The only licences containing `LGPL` are **optional alternatives**, not
obligations:

- `r-efi` — `MIT OR Apache-2.0 OR LGPL-2.1-or-later`
- `r-efi` — `MIT OR Apache-2.0 OR LGPL-2.1-or-later`

`r-efi` and the bzip2 C sources are offered under LGPL-2.1-or-later *as well as*
MIT and/or Apache-2.0. Zipee builds under the MIT/Apache-2.0 alternatives, so
**no LGPL obligation is triggered** and no LGPL text ships with Zipee.

## Complete list

### `MIT OR Apache-2.0`

- aes
- anstream
- anstyle
- anstyle-parse
- anstyle-query
- anstyle-wincon
- arbitrary
- bitflags
- block-buffer
- bumpalo
- bzip2
- cc
- cfg-if
- cipher
- clap
- clap_builder
- clap_derive
- clap_lex
- colorchoice
- cpufeatures
- crc32fast
- crossbeam-utils
- crypto-common
- deranged
- derive_arbitrary
- digest
- displaydoc
- errno
- find-msvc-tools
- flate2
- getrandom
- getrandom
- hashbrown
- heck
- hmac
- inout
- is_terminal_polyfill
- jobserver
- js-sys
- libc
- log
- num-conv
- once_cell
- once_cell_polyfill
- pbkdf2
- pkg-config
- powerfmt
- proc-macro2
- quote
- rustversion
- serde_core
- serde_derive
- sha1
- shlex
- syn
- syn
- tempfile
- thiserror
- thiserror-impl
- time
- time-core
- typenum
- wasm-bindgen
- wasm-bindgen-macro
- wasm-bindgen-macro-support
- wasm-bindgen-shared
- windows-link
- windows-sys

### `Apache-2.0 OR MIT`

- equivalent
- fastrand
- indexmap
- utf8parse
- zeroize
- zeroize_derive

### `MIT`

- generic-array
- simd-adler32
- strsim
- zip
- zstd

### `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT`

- linux-raw-sys
- rustix
- wasip2
- wit-bindgen

### `BSD-3-Clause`

- subtle
- zstd-safe
- zstd-sys

### `Apache-2.0`

- zipee-cli
- zipee-engine
- zopfli

### `MIT/Apache-2.0`

- bzip2-sys
- version_check

### `MIT OR Apache-2.0 OR LGPL-2.1-or-later`

- r-efi
- r-efi

### `0BSD OR MIT OR Apache-2.0`

- adler2

### `CC0-1.0 OR MIT-0 OR Apache-2.0`

- constant_time_eq

### `Unlicense OR MIT`

- memchr

### `MIT OR Zlib OR Apache-2.0`

- miniz_oxide

### `(MIT OR Apache-2.0) AND Unicode-3.0`

- unicode-ident

## Licence texts

The full text of each licence lives with the dependency that uses it, at
`https://crates.io/crates/<name>`. The licences involved are:

- Apache License 2.0 — <https://www.apache.org/licenses/LICENSE-2.0>
- MIT License — <https://opensource.org/licenses/MIT>
- BSD 3-Clause — <https://opensource.org/licenses/BSD-3-Clause>
- The Unlicense — <https://unlicense.org>
- CC0 1.0 — <https://creativecommons.org/publicdomain/zero/1.0/>

All are permissive and compatible with distributing Zipee under Apache-2.0.
No dependency is vendored into this repository.
