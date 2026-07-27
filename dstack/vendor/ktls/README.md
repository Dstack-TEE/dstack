[![test pipeline](https://github.com/hapsoc/ktls/actions/workflows/test.yml/badge.svg)](https://github.com/hapsoc/ktls/actions/workflows/test.yml?query=branch%3Amain)
[![Coverage Status (codecov.io)](https://codecov.io/gh/hapsoc/ktls/branch/main/graph/badge.svg)](https://codecov.io/gh/hapsoc/ktls/)
[![Crates.io](https://img.shields.io/crates/v/ktls)](https://crates.io/crates/ktls)
[![license: MIT/Apache-2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

# ktls

Configures kTLS ([kernel TLS
offload](https://www.kernel.org/doc/html/latest/networking/tls-offload.html))
for any type that implements `AsRawFd`, given a rustls `ServerConnection`.

## License

This project is primarily distributed under the terms of both the MIT license
and the Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for details.
