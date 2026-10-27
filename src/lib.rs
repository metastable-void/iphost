#![cfg_attr(docsrs, feature(doc_cfg))]

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
