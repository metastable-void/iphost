use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use fqdn::FQDN;

use crate::IpHost;

/// DNS resolver used to resolve FQDNs.
///
/// Can be swapped at runtime with [`IpHostResolver::set_resolver`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Resolver {
    /// The operating system's resolver (`getaddrinfo(3)`).
    #[default]
    System,

    /// Explicitly configured nameservers. The system hosts file is not consulted; `localhost`
    /// is still answered locally (RFC 6761).
    #[cfg(feature = "custom")]
    #[cfg_attr(docsrs, doc(cfg(feature = "custom")))]
    Static(crate::StaticResolverConfig),

    /// DNS servers advertised by IPv6 routers (RDNSS).
    #[cfg(feature = "ra")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ra")))]
    Ra(crate::RaResolverConfig),

    /// DNS servers from stateless DHCPv6 (Information-Request).
    #[cfg(feature = "dhcpv6")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dhcpv6")))]
    Dhcpv6(crate::Dhcpv6ResolverConfig),

    /// DNS servers from DHCPv6 or Router Advertisements, whichever is available, preferring
    /// DHCPv6. Uses only the sources whose features are enabled.
    #[cfg(any(feature = "ra", feature = "dhcpv6"))]
    #[cfg_attr(docsrs, doc(cfg(any(feature = "ra", feature = "dhcpv6"))))]
    Ipv6(crate::Ipv6ResolverConfig),
}

impl Resolver {
    /// Blocking lookup. MUST NOT require the caller to be outside of (or inside) a tokio runtime.
    fn lookup(&self, fqdn: &FQDN) -> io::Result<Vec<IpAddr>> {
        match self {
            Resolver::System => Ok((fqdn.to_string(), 0)
                .to_socket_addrs()?
                .map(|a| a.ip())
                .collect()),
            #[cfg(feature = "custom")]
            Resolver::Static(config) => config.lookup(fqdn),
            #[cfg(feature = "ra")]
            Resolver::Ra(config) => config.lookup(fqdn),
            #[cfg(feature = "dhcpv6")]
            Resolver::Dhcpv6(config) => config.lookup(fqdn),
            #[cfg(any(feature = "ra", feature = "dhcpv6"))]
            Resolver::Ipv6(config) => config.lookup(fqdn),
        }
    }
}

/// Resolver into IP addresses for a hostname.
///
/// Clones share the same state.
#[derive(Debug, Clone)]
pub struct IpHostResolver {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    state: Mutex<State>,
    use_cached_on_error: bool,
    retain_stale_values: bool,
}

#[derive(Debug)]
struct State {
    ip_host: IpHost,
    resolver: Resolver,
    v4_addr: Option<Ipv4Addr>,
    v6_addr: Option<Ipv6Addr>,
    /// Bumped on every hostname or resolver change, so that in-flight lookups for the old
    /// configuration are discarded.
    generation: u64,
}

impl State {
    /// Forgets results from the previous configuration.
    fn reset(&mut self) {
        (self.v4_addr, self.v6_addr) = match &self.ip_host {
            IpHost::V4Addr(addr) => (Some(*addr), None),
            IpHost::V6Addr(addr) => (None, Some(*addr)),
            IpHost::Fqdn(_) => (None, None),
        };
        self.generation += 1;
    }
}

impl IpHostResolver {
    /// Creates a new resolver instance for a particular hostname. (no-op for IP addresses)
    ///
    /// This method accepts options about what to do on error conditions.
    ///
    /// - `use_cached_on_error`: whether to use cached results when a resolution error occurs.
    /// - `retain_stale_values`: whether to keep the cached IPv4 / IPv6 address when a resolution returns no address of that family.
    pub fn new_with_config(
        ip_host: IpHost,
        use_cached_on_error: bool,
        retain_stale_values: bool,
    ) -> Self {
        let mut state = State {
            ip_host,
            resolver: Resolver::default(),
            v4_addr: None,
            v6_addr: None,
            generation: 0,
        };
        state.reset();

        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(state),
                use_cached_on_error,
                retain_stale_values,
            }),
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

    /// Sets the DNS resolver to use, builder-style.
    pub fn with_resolver(self, resolver: Resolver) -> Self {
        self.set_resolver(resolver);
        self
    }

    // State is consistent after every field assignment, so a poisoned lock is safe to reuse.
    fn state(&self) -> MutexGuard<'_, State> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Returns the IPv4 address currently we have for this hostname without resolving it now.
    pub fn ipv4_addr(&self) -> Option<Ipv4Addr> {
        self.state().v4_addr
    }

    /// Returns the IPv6 address currently we have for this hostname without resolving it now.
    pub fn ipv6_addr(&self) -> Option<Ipv6Addr> {
        self.state().v6_addr
    }

    /// Returns the current hostname.
    pub fn ip_host(&self) -> IpHost {
        self.state().ip_host.clone()
    }

    /// Returns the current DNS resolver.
    pub fn resolver(&self) -> Resolver {
        self.state().resolver.clone()
    }

    /// Replaces the hostname value, returning the old one.
    ///
    /// Cached addresses are reset, and any in-flight resolution for the old hostname is discarded.
    /// When the new value is equal to the old value, nothing changes.
    pub fn replace_ip_host(&self, new: IpHost) -> IpHost {
        let mut state = self.state();
        if state.ip_host == new {
            return new;
        }
        let old = std::mem::replace(&mut state.ip_host, new);
        state.reset();
        old
    }

    /// Replaces the DNS resolver, returning the old one.
    ///
    /// Cached addresses are reset, and any in-flight resolution with the old resolver is
    /// discarded, so nothing from the old resolver is used afterwards.
    pub fn set_resolver(&self, resolver: Resolver) -> Resolver {
        let mut state = self.state();
        let old = std::mem::replace(&mut state.resolver, resolver);
        state.reset();
        old
    }

    fn cached(state: &State) -> Vec<IpAddr> {
        state
            .v6_addr
            .map(IpAddr::V6)
            .into_iter()
            .chain(state.v4_addr.map(IpAddr::V4))
            .collect()
    }

    /// Resolves the hostname, refreshes the stored values, and returns all resolved IP addresses.
    ///
    /// This WILL block the calling thread. It is safe to call from `tokio::task::spawn_blocking()`.
    pub fn resolve(&self) -> Vec<IpAddr> {
        let (fqdn, resolver, generation) = {
            let state = self.state();
            match &state.ip_host {
                IpHost::V4Addr(addr) => return vec![IpAddr::V4(*addr)],
                IpHost::V6Addr(addr) => return vec![IpAddr::V6(*addr)],
                IpHost::Fqdn(fqdn) => (fqdn.clone(), state.resolver.clone(), state.generation),
            }
        };

        // No lock held here: lookups may take a long time.
        let res = resolver.lookup(&fqdn);

        let mut state = self.state();
        if state.generation != generation {
            // The hostname or resolver changed while resolving.
            return Self::cached(&state);
        }

        let addrs = match res {
            Ok(addrs) => addrs,
            Err(_e) => {
                #[cfg(feature = "tracing")]
                tracing::debug!(error = %_e, %fqdn, "Resolution failed");
                return if self.inner.use_cached_on_error {
                    Self::cached(&state)
                } else {
                    Vec::new()
                };
            }
        };

        let (v4_cand, v6_cand) = stable_pick(&addrs, state.v4_addr, state.v6_addr);
        if v4_cand.is_some() || !self.inner.retain_stale_values {
            state.v4_addr = v4_cand;
        }
        if v6_cand.is_some() || !self.inner.retain_stale_values {
            state.v6_addr = v6_cand;
        }
        addrs
    }

    /// Resolves the hostname, returning a separated pair of `Vec<Ipv4Addr>` and `Vec<Ipv6Addr>`.
    ///
    /// This WILL block the calling thread.
    pub fn resolve_v4_and_v6(&self) -> (Vec<Ipv4Addr>, Vec<Ipv6Addr>) {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for addr in self.resolve() {
            match addr {
                IpAddr::V4(addr) => v4.push(addr),
                IpAddr::V6(addr) => v6.push(addr),
            }
        }
        (v4, v6)
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

/// Stable resolution: keeps the previous address if it is still present, otherwise picks the first one.
fn stable_pick(
    addrs: &[IpAddr],
    prev_v4: Option<Ipv4Addr>,
    prev_v6: Option<Ipv6Addr>,
) -> (Option<Ipv4Addr>, Option<Ipv6Addr>) {
    let mut v4_cand = None;
    let mut v6_cand = None;
    for addr in addrs {
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
    (v4_cand, v6_cand)
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

    #[test]
    fn stable_pick_keeps_previous() {
        let a = Ipv4Addr::new(192, 0, 2, 1);
        let b = Ipv4Addr::new(192, 0, 2, 2);
        let addrs = [IpAddr::V4(a), IpAddr::V4(b)];
        assert_eq!(stable_pick(&addrs, Some(b), None), (Some(b), None));
        assert_eq!(stable_pick(&addrs, None, None), (Some(a), None));
        assert_eq!(
            stable_pick(&addrs, Some(Ipv4Addr::LOCALHOST), None),
            (Some(a), None)
        );
    }

    #[test]
    fn replace_resets_cache() {
        let resolver = IpHostResolver::new(IpHost::V4Addr(Ipv4Addr::LOCALHOST));
        assert_eq!(resolver.ipv4_addr(), Some(Ipv4Addr::LOCALHOST));
        let old = resolver.replace_ip_host(IpHost::V6Addr(Ipv6Addr::LOCALHOST));
        assert_eq!(old, IpHost::V4Addr(Ipv4Addr::LOCALHOST));
        assert_eq!(resolver.ipv4_addr(), None);
        assert_eq!(resolver.ipv6_addr(), Some(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn set_resolver_resets_cache() {
        let resolver = IpHostResolver::new("localhost".parse().unwrap());
        resolver.resolve();
        assert!(resolver.ipv4_addr().is_some());
        resolver.set_resolver(Resolver::System);
        assert_eq!(resolver.ipv4_addr(), None);
        // Literal addresses stay, as they need no resolver.
        let literal = IpHostResolver::new(IpHost::V4Addr(Ipv4Addr::LOCALHOST));
        literal.set_resolver(Resolver::System);
        assert_eq!(literal.ipv4_addr(), Some(Ipv4Addr::LOCALHOST));
    }
}
