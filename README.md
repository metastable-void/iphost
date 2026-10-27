# iphost Rust library

Stable hostname resolution library that supports storing a hostname in following variants:

- Static IPv4 address
- Static IPv6 address
- Dynamically resolved FQDN

FQDNs are resolved with the system resolver by default. The DNS resolver can be swapped at runtime.

## Features

- `serde` (default): `Serialize` / `Deserialize` for `IpHost`.
- `tracing` (default): logging via `tracing`.
- `broadcast` (default): subscribing to address changes of `AutoIpHostResolver`.
- `custom`: `Resolver::Static` to query explicitly configured nameservers (via hickory-resolver), optionally bound to an interface or a VRF (Linux VRF, OpenBSD rdomain, FreeBSD FIB).

## License
Apache-2.0 or MPL-2.0.
