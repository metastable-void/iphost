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
- `dhcpv6` (implies `custom`): `Resolver::Dhcpv6` to use the DNS servers from stateless DHCPv6 (Information-Request) on an interface. Needs to bind UDP port 546. The Client Identifier must be chosen explicitly, since some networks require a particular one.

## Network-specific notes

This crate is not specific to any country or network. Most DHCPv6 servers accept any Client Identifier (or none), but some networks are stricter. `ClientId::Raw` sends an exact DUID, for networks that expect a specific one. Known examples follow.

### NTT FLET'S (NGN) lines in Japan

On RA lines (フレッツ 光ネクスト IPoE without an HGW), DHCPv6 Information-Requests go to the NGN directly. NTT's interface specification (技術参考資料 IP通信網サービスのインタフェース 第三分冊, §2.4.2.1.4) requires a **DUID-LL with hardware type 1 made from the terminal's MAC address**, and the NGN is reported to silently ignore other DUIDs. Use:

```rust
// The plain 6-byte MAC address of eth0 (here 00:11:22:33:44:55), not a DUID;
// it is sent as DUID-LL 00:03:00:01:00:11:22:33:44:55.
Dhcpv6ResolverConfig::new("eth0", ClientId::DuidLl([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))?
```

`ClientId::None` (anonymous, RFC 7844) and `ClientId::RandomDuidLl` (random locally administered MAC) are available for other networks, but are most likely ignored by the NGN. On DHCPv6-PD lines (with an HGW, including all フレッツ 光クロス lines), the HGW answers instead; its requirements are not documented.

## License
Apache-2.0 or MPL-2.0.
