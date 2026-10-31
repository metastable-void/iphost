# iphost Rust library

Stable hostname resolution library that supports storing a hostname in following variants:

- Static IPv4 address
- Static IPv6 address
- Dynamically resolved FQDN

FQDNs are resolved with the system resolver by default. The DNS resolver can be swapped at runtime.

## Resolution behavior

`IpHostResolver` keeps one IPv4 and one IPv6 address per hostname. It keeps the previous address for as long as lookups still return it, so the chosen address does not flap between the records of a name. `AutoIpHostResolver` resolves periodically on a background thread and, with the `broadcast` feature, reports when either address changes.

Two options control error handling (`IpHostResolver::new_with_config`):

- `use_cached_on_error` (default `true`): when a lookup fails, `resolve()` returns the cached addresses instead of nothing. A failed lookup never changes the cache.
- `retain_stale_values` (default `false`): when a lookup succeeds but returns no address of a family, the cached address of that family is kept instead of cleared.

With the built-in resolvers (`custom`, `ra`, `dhcpv6`), A and AAAA are queried separately. If one fails (a timeout, SERVFAIL, etc.) while the other succeeds, that family is treated as a failed lookup and its cached address stays. An NXDOMAIN or empty answer for one family is not a failure. With `Resolver::System`, the operating system decides how partial failures are reported.

Replacing the hostname or the resolver resets the cache. A lookup still in flight for the old configuration is discarded.

`Resolver::System.max_lookup_time()` is `None`: libc controls its duration. Dropping the last `AutoIpHostResolver` clone signals shutdown without waiting, but its worker cannot exit until an ongoing lookup returns. Dropping interest, timing out a caller's wait, or replacing a hostname does not cancel libc execution.

## Features

- `serde` (default): `Serialize` / `Deserialize` for `IpHost`.
- `tracing` (default): logging via `tracing`.
- `broadcast` (default): subscribing to address changes of `AutoIpHostResolver`.
- `custom`: `Resolver::Static` to query explicitly configured nameservers with a built-in stub client (UDP, TCP on truncation; no dependencies beyond `socket2` and `libc`), optionally bound to an interface or a VRF (Linux VRF, OpenBSD rdomain, FreeBSD FIB). `Resolver::max_lookup_time` bounds how long a lookup blocks.
- `ra` (implies `custom`): `Resolver::Ra` to use the DNS servers advertised by IPv6 routers (RDNSS) on an interface. Reads RAs on a raw ICMPv6 socket and sends Router Solicitations when privileged; falls back to the kernel's RA options via netlink when unprivileged on Linux.
- `dhcpv6` (implies `custom`): `Resolver::Dhcpv6` to use the DNS servers from stateless DHCPv6 (Information-Request) on an interface. Needs to bind UDP port 546. The Client Identifier must be chosen explicitly, since some networks require a particular one.
- With `ra` and/or `dhcpv6`: `Resolver::Ipv6` uses DHCPv6 or Router Advertisements on an interface, whichever is available, preferring DHCPv6. Only the enabled sources are used: with just `ra` it behaves like `Resolver::Ra` (and ignores the Client Identifier), with just `dhcpv6` like `Resolver::Dhcpv6`.

`RaResolverConfig` maintains up to 64 distinct RDNSS addresses per listener/interface, including stale entries. An advertisement refreshes only the listed addresses; a zero lifetime withdraws only that address, including its stale copy. Refreshed addresses come first in advertised order, followed by omitted entries. At capacity, eviction removes only omitted entries: expired ones first, then the earliest finite expiry, then infinite lifetimes, with address byte order breaking ties. An advertisement with more addresses than the capacity keeps its first 64. When no live servers remain, the documented stale-server fallback still applies. Only the first three current servers are queried.

`Ipv6ResolverConfig::with_failure_fallback(true)` opts into trying RA servers when DHCPv6 DNS fails. The default still selects only DHCPv6's nonempty list, or RA if DHCPv6 has none. With fallback enabled, A and AAAA independently exhaust the DHCPv6 list before trying RA; positive answers, NXDOMAIN, and NOERROR/NODATA settle that family. Each lookup starts with DHCPv6 again. `nameservers()` still returns the preferred list; the source accessors expose each source's list. Discovery waits up to three seconds once, and snapshots up to three servers per source. The lookup bound is 63 seconds when both sources started and fallback is enabled, otherwise 33 seconds. Cache options, binding, link-local scope and VRF/routing-domain support are unchanged.

DHCPv6 configurations share their receive socket only within the same
network namespace and interface. Linux and Android identify the namespace
with `SO_NETNS_COOKIE`; older kernels without that option need readable
`/proc/thread-self/ns/net`. No additional privilege or procfs access is
needed when the socket option is available. Other platforms retain their
existing interface-based sharing.

## Built-in stub client

The `custom`, `ra` and `dhcpv6` resolvers share a minimal stub client (RFC 1035):

- Recursive queries only, so the nameservers must be recursive resolvers.
- A and AAAA are queried in parallel. Each query uses a fresh socket, a port the OS picks and a random ID, and only accepts a reply that matches its ID and question.
- UDP without EDNS. Truncated answers are retried over TCP.
- Names are queried exactly as given. There are no search domains, no hosts file and no `localhost` special case.
- Nameservers are asked in order, and the list is tried twice, with a 5 s timeout per query. NXDOMAIN is final, and other failures move on to the next nameserver. `Resolver::max_lookup_time` gives the upper bound. Discovered nameservers (RA, DHCPv6) are limited to the first three, after waiting up to 3 s for them to appear.
- A name with neither A nor AAAA records is an error, as with `getaddrinfo`.
- There is no DNSSEC validation. The nameservers, and the network path to them, are trusted.

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
