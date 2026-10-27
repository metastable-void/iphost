//! Stable hostname resolution.
//!
//! An [`IpHost`] is a static IPv4 address, a static IPv6 address, or an [`FQDN`] to resolve.
//! [`IpHostResolver`] resolves it on demand and keeps one IPv4 and one IPv6 address, preferring
//! the previous address while it is still returned, so the chosen address does not flap between
//! the records of a name. [`AutoIpHostResolver`] does the same periodically on a background
//! thread and (with the `broadcast` feature) reports changes.
//!
//! FQDNs are resolved with the operating system's resolver by default ([`Resolver::System`]).
//! Optional features add a built-in stub DNS client with explicitly configured nameservers
//! (`custom`), or nameservers discovered from IPv6 Router Advertisements (`ra`) or stateless
//! DHCPv6 (`dhcpv6`); see [`Resolver`].
//!
//! ```
//! use iphost::{IpHost, IpHostResolver};
//! use std::net::Ipv4Addr;
//!
//! let resolver = IpHostResolver::new("192.0.2.1".parse::<IpHost>().unwrap());
//! assert_eq!(resolver.resolve_v4(), [Ipv4Addr::new(192, 0, 2, 1)]);
//! assert_eq!(resolver.ipv6_addr(), None);
//! ```
//!
//! # Features
//!
//! - `serde` (default): `Serialize` / `Deserialize` for [`IpHost`].
//! - `tracing` (default): logging via `tracing`.
//! - `broadcast` (default): `AutoIpHostResolver::subscribe_changes`.
//! - `custom`: `Resolver::Static`, `StaticResolverConfig`, `BindDevice`.
//! - `ra` (implies `custom`): `Resolver::Ra`, `RaResolverConfig`, and `Resolver::Ipv6`.
//! - `dhcpv6` (implies `custom`): `Resolver::Dhcpv6`, `Dhcpv6ResolverConfig`, and `Resolver::Ipv6`.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

mod auto;
#[cfg(feature = "custom")]
mod custom;
#[cfg(feature = "dhcpv6")]
mod dhcpv6;
#[cfg(any(feature = "ra", feature = "dhcpv6"))]
mod duid;
mod host;
#[cfg(any(feature = "ra", feature = "dhcpv6"))]
mod ipv6;
#[cfg(feature = "ra")]
mod ra;
mod resolver;

pub use auto::*;
#[cfg(feature = "custom")]
pub use custom::{BindDevice, StaticResolverConfig};
#[cfg(feature = "dhcpv6")]
pub use dhcpv6::Dhcpv6ResolverConfig;
#[cfg(any(feature = "ra", feature = "dhcpv6"))]
pub use duid::ClientId;
pub use fqdn::FQDN;
pub use host::IpHost;
#[cfg(any(feature = "ra", feature = "dhcpv6"))]
pub use ipv6::Ipv6ResolverConfig;
#[cfg(feature = "ra")]
pub use ra::{RaResolverConfig, RaSource};
pub use resolver::{IpHostResolver, Resolver};
