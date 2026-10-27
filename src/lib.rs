#![cfg_attr(docsrs, feature(doc_cfg))]

mod auto;
mod host;
mod resolver;

pub use auto::*;
pub use fqdn::FQDN;
pub use host::IpHost;
pub use resolver::{IpHostResolver, Resolver};
