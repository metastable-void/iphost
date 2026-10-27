#![cfg_attr(docsrs, feature(doc_cfg))]

mod auto;
#[cfg(feature = "custom")]
mod custom;
#[cfg(feature = "dhcpv6")]
mod dhcpv6;
mod host;
#[cfg(feature = "ra")]
mod ra;
mod resolver;

pub use auto::*;
#[cfg(feature = "custom")]
pub use custom::{BindDevice, StaticResolverConfig};
#[cfg(feature = "dhcpv6")]
pub use dhcpv6::{ClientId, Dhcpv6ResolverConfig};
pub use fqdn::FQDN;
pub use host::IpHost;
#[cfg(feature = "ra")]
pub use ra::RaResolverConfig;
pub use resolver::{IpHostResolver, Resolver};
