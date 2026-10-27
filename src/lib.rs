#![cfg_attr(docsrs, feature(doc_cfg))]

mod auto;
#[cfg(feature = "custom")]
mod custom;
mod host;
#[cfg(feature = "ra")]
mod ra;
mod resolver;

pub use auto::*;
#[cfg(feature = "custom")]
pub use custom::{BindDevice, StaticResolverConfig};
pub use fqdn::FQDN;
pub use host::IpHost;
#[cfg(feature = "ra")]
pub use ra::RaResolverConfig;
pub use resolver::{IpHostResolver, Resolver};
