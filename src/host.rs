use std::fmt::Display;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use fqdn::FQDN;

/// Representation for a hostname, either an IP address or an FQDN.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IpHost {
    /// Concrete IPv4 address.
    V4Addr(Ipv4Addr),

    /// Concrete IPv6 address.
    V6Addr(Ipv6Addr),

    /// Unresolved FQDN.
    Fqdn(FQDN),
}

impl Display for IpHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpHost::V4Addr(addr) => addr.fmt(f),
            IpHost::V6Addr(addr) => addr.fmt(f),
            IpHost::Fqdn(fqdn) => fqdn.fmt(f),
        }
    }
}

impl FromStr for IpHost {
    type Err = std::io::Error;
    fn from_str(v: &str) -> Result<Self, Self::Err> {
        if let Ok(addr) = v.parse::<Ipv4Addr>() {
            Ok(IpHost::V4Addr(addr))
        } else if let Ok(addr) = v.parse::<Ipv6Addr>() {
            Ok(IpHost::V6Addr(addr))
        } else if let Ok(fqdn) = v.parse::<FQDN>() {
            Ok(IpHost::Fqdn(fqdn))
        } else {
            Err(Self::Err::other("IP address or FQDN expected"))
        }
    }
}

#[cfg(feature = "serde")]
mod serialization {
    use super::IpHost;
    use serde::de::{self, Deserialize, Deserializer};
    use serde::ser::{Serialize, Serializer};

    #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
    impl<'de> Deserialize<'de> for IpHost {
        fn deserialize<D>(deserializer: D) -> Result<IpHost, D::Error>
        where
            D: Deserializer<'de>,
        {
            let v = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
            v.parse().map_err(|_| {
                de::Error::invalid_value(de::Unexpected::Str(&v), &"IP address or FQDN")
            })
        }
    }

    #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
    impl Serialize for IpHost {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.collect_str(self)
        }
    }
}
