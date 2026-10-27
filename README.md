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
- `ra` (implies `custom`): `Resolver::Ra` to use the DNS servers advertised by IPv6 routers (RDNSS) on an interface. Reads RAs on a raw ICMPv6 socket and sends Router Solicitations when privileged; falls back to the kernel's RA options via netlink when unprivileged on Linux.

## License
Apache-2.0 or MPL-2.0.
