#![cfg_attr(docsrs, feature(doc_srs))]

mod auto;

use std::fmt::Display;
pub(crate) use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::sync::{Arc, RwLock, atomic::AtomicBool};

pub use auto::*;
pub use fqdn::FQDN;

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
        match self.clone() {
            IpHost::V4Addr(addr) => f.write_str(&addr.to_string()),
            IpHost::V6Addr(addr) => f.write_str(&addr.to_string()),
            IpHost::Fqdn(fqdn) => f.write_str(&fqdn.to_string()),
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
    use super::*;
    use serde::de::{self, Deserialize, Deserializer, Visitor};
    use serde::ser::{Serialize, Serializer};
    use std::fmt;

    struct IpHostVisitor;

    impl<'de> Visitor<'de> for IpHostVisitor {
        type Value = IpHost;
        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("Expected an FQDN or IP address")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if let Ok(addr) = v.parse::<Ipv4Addr>() {
                Ok(IpHost::V4Addr(addr))
            } else if let Ok(addr) = v.parse::<Ipv6Addr>() {
                Ok(IpHost::V6Addr(addr))
            } else if let Ok(fqdn) = v.parse::<FQDN>() {
                Ok(IpHost::Fqdn(fqdn))
            } else {
                Err(E::invalid_value(
                    de::Unexpected::Str(v),
                    &"IP address or FQDN",
                ))
            }
        }
    }

    #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
    impl<'de> Deserialize<'de> for IpHost {
        fn deserialize<D>(deserializer: D) -> Result<IpHost, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_str(IpHostVisitor)
        }
    }

    #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
    impl Serialize for IpHost {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(&self.to_string())
        }
    }
}

/// Resolver into IP addresses for a hostname.
#[derive(Debug, Clone)]
pub struct IpHostResolver {
    ip_host: Arc<RwLock<IpHost>>,
    prev_v4_addr: Arc<RwLock<Option<Ipv4Addr>>>,
    prev_v6_addr: Arc<RwLock<Option<Ipv6Addr>>>,
    is_locked: Arc<AtomicBool>,
    use_cached_on_error: Arc<bool>,
    retain_stale_values: Arc<bool>,
}

impl IpHostResolver {
    /// Creates a new resolver instance for a particular hostname. (no-op for IP addresses)
    ///
    /// This method accepts options about what to do on error conditions.
    ///
    /// - `use_cached_on_error`: whether to use cached results when a resolution error occurs.
    /// - `retain_stale_values`: whether to keep cached results when the resolution results in an empty address set.
    pub fn new_with_config(
        ip_host: IpHost,
        use_cached_on_error: bool,
        retain_stale_values: bool,
    ) -> Self {
        let v4_addr = if let IpHost::V4Addr(addr) = &ip_host {
            Some(*addr)
        } else {
            None
        };

        let v6_addr = if let IpHost::V6Addr(addr) = &ip_host {
            Some(*addr)
        } else {
            None
        };

        Self {
            ip_host: Arc::new(RwLock::new(ip_host)),
            prev_v4_addr: Arc::new(RwLock::new(v4_addr)),
            prev_v6_addr: Arc::new(RwLock::new(v6_addr)),
            is_locked: Arc::new(AtomicBool::new(false)),
            use_cached_on_error: Arc::new(use_cached_on_error),
            retain_stale_values: Arc::new(retain_stale_values),
        }
    }

    /// Creates a new resolver instance for a particular hostname. (no-op for IP addresses)
    ///
    /// This method uses the following default values.
    ///
    /// - `use_cached_on_error`: `true`
    /// - `retain_stale_values`: `false`
    pub fn new(ip_host: IpHost) -> Self {
        Self::new_with_config(ip_host, true, false)
    }

    /// Returns the IPv4 address currently we have for this hostname without resolving it now.
    pub fn ipv4_addr(&self) -> Option<Ipv4Addr> {
        if let Ok(lock) = self.prev_v4_addr.read() {
            *lock
        } else {
            None
        }
    }

    /// Returns the IPv6 address currently we have for this hostname without resolving it now.
    pub fn ipv6_addr(&self) -> Option<Ipv6Addr> {
        if let Ok(lock) = self.prev_v6_addr.read() {
            *lock
        } else {
            None
        }
    }

    fn do_transaction<T, F: FnOnce() -> T>(&self, op: F) -> Option<T> {
        if self
            .is_locked
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            return None;
        }

        let ret = op();

        self.is_locked
            .store(false, std::sync::atomic::Ordering::SeqCst);
        Some(ret)
    }

    /// Atomically replaces the hostname value.
    ///
    /// Returns Ok(old_val) if the swap succeeds, and
    /// returns Err(new_val) if the swap fails (there is some concurrent transaction).
    ///
    /// When the new value is equal to the old value, this returns Ok(val).
    ///
    /// This MAY block the calling thread.
    pub fn replace_ip_host(&self, new: IpHost) -> Result<IpHost, IpHost> {
        let v4_addr = if let IpHost::V4Addr(addr) = &new {
            Some(*addr)
        } else {
            None
        };

        let v6_addr = if let IpHost::V6Addr(addr) = &new {
            Some(*addr)
        } else {
            None
        };

        let new_clone = new.clone();

        let ret = self.do_transaction(|| {
            if let Ok(lock) = self.ip_host.read()
                && *lock == new
            {
                return Ok(new);
            }

            let value = if let Ok(mut lock) = self.ip_host.write() {
                let old = lock.clone();
                *lock = new;
                Ok(old)
            } else {
                Err(new)
            };

            if value.is_ok() {
                if let Some(addr) = v4_addr {
                    if let Ok(mut lock) = self.prev_v4_addr.write() {
                        *lock = Some(addr);
                    }
                    if let Ok(mut lock) = self.prev_v6_addr.write() {
                        *lock = None;
                    }
                } else if let Some(addr) = v6_addr {
                    if let Ok(mut lock) = self.prev_v4_addr.write() {
                        *lock = None;
                    }
                    if let Ok(mut lock) = self.prev_v6_addr.write() {
                        *lock = Some(addr);
                    }
                }
            }

            value
        });

        ret.unwrap_or(Err(new_clone))
    }

    /// Resolves the hostname, refreshes the stored values, and returns all resolved IP addresses.
    ///
    /// This WILL block the calling thread.
    #[inline]
    pub fn resolve(&self) -> Vec<IpAddr> {
        let ret = self
            .do_transaction(|| {
                let prev_v4 = self.ipv4_addr();
                let prev_v6 = self.ipv6_addr();

                let host = if let Ok(lock) = self.ip_host.read() {
                    lock.clone()
                } else {
                    return None;
                };

                let fqdn = match host {
                    IpHost::V4Addr(addr) => return Some(vec![IpAddr::V4(addr)]),
                    IpHost::V6Addr(addr) => return Some(vec![IpAddr::V6(addr)]),
                    IpHost::Fqdn(fqdn) => fqdn,
                };

                let ret = (fqdn.to_string(), 0).to_socket_addrs().ok().map(|ok| {
                    ok.map(|a| match a {
                        SocketAddr::V4(addr) => IpAddr::V4(*addr.ip()),
                        SocketAddr::V6(addr) => IpAddr::V6(*addr.ip()),
                    })
                    .collect()
                });

                let ret: Vec<IpAddr> = ret?;

                let mut v4_cand = None;
                let mut v6_cand = None;
                // Stable resolution (if the same address as before is available, use that)
                for addr in ret.iter() {
                    match *addr {
                        IpAddr::V4(addr) => {
                            if prev_v4 == Some(addr) || v4_cand.is_none() {
                                v4_cand = Some(addr);
                            }
                        }
                        IpAddr::V6(addr) => {
                            if prev_v6 == Some(addr) || v6_cand.is_none() {
                                v6_cand = Some(addr);
                            }
                        }
                    }
                }

                if (v4_cand.is_some() || !*self.retain_stale_values)
                    && let Ok(mut lock) = self.prev_v4_addr.write()
                {
                    *lock = v4_cand;
                }
                if (v6_cand.is_some() || !*self.retain_stale_values)
                    && let Ok(mut lock) = self.prev_v6_addr.write()
                {
                    *lock = v6_cand;
                }
                Some(ret)
            })
            .flatten();

        if ret.is_none() && *self.use_cached_on_error {
            let mut values = Vec::with_capacity(2);
            if let Some(addr) = self.ipv6_addr() {
                values.push(IpAddr::V6(addr));
            }
            if let Some(addr) = self.ipv4_addr() {
                values.push(IpAddr::V4(addr));
            }
            values
        } else {
            ret.unwrap_or_default()
        }
    }

    /// Resolves the hostname, returning a separated pair of `Vec<Ipv4Addr>` and `Vec<Ipv6Addr>`.
    ///
    /// This WILL block the calling thread.
    #[inline]
    pub fn resolve_v4_and_v6(&self) -> (Vec<Ipv4Addr>, Vec<Ipv6Addr>) {
        let addrs = self.resolve();
        let (v4iter, v6iter) = addrs.iter().partition::<Vec<_>, _>(|a| a.is_ipv4());
        let v4addrs = v4iter
            .iter()
            .map(|a| match a {
                IpAddr::V4(addr) => *addr,
                _ => unreachable!(),
            })
            .collect::<Vec<_>>();
        let v6addrs = v6iter
            .iter()
            .map(|a| match a {
                IpAddr::V6(addr) => *addr,
                _ => unreachable!(),
            })
            .collect::<Vec<_>>();

        (v4addrs, v6addrs)
    }

    /// Resolves the hostname to IPv4 addresses.
    ///
    /// This WILL block the calling thread.
    ///
    /// NOTE: Use resolve_v4_and_v6() if you want both IPv4 and IPv6 addresses.
    pub fn resolve_v4(&self) -> Vec<Ipv4Addr> {
        self.resolve_v4_and_v6().0
    }

    /// Resolves the hostname to IPv6 addresses.
    ///
    /// This WILL block the calling thread.
    ///
    /// NOTE: Use resolve_v4_and_v6() if you want both IPv4 and IPv6 addresses.
    pub fn resolve_v6(&self) -> Vec<Ipv6Addr> {
        self.resolve_v4_and_v6().1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_localhost() {
        let loopback = Ipv4Addr::new(127, 0, 0, 1);
        let ip_host = "localhost"
            .parse::<IpHost>()
            .expect("Failed to construct the IpHost struct");
        let resolver = IpHostResolver::new(ip_host);
        let v4_addrs = resolver.resolve_v4();
        assert!(
            v4_addrs.contains(&loopback),
            "Failed to resolve `localhost`"
        );
        assert_eq!(
            resolver.ipv4_addr(),
            Some(loopback),
            "Cached value of `localhost` resolution did not contain 127.0.0.1"
        );
    }
}
