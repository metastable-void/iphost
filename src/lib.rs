#![cfg_attr(docsrs, feature(doc_cfg))]

mod auto;
#[cfg(feature = "custom")]
mod custom;
mod host;
mod resolver;

pub use auto::*;
#[cfg(feature = "custom")]
pub use custom::{BindDevice, StaticResolverConfig};
pub use fqdn::FQDN;
pub use host::IpHost;
pub use resolver::{IpHostResolver, Resolver};
