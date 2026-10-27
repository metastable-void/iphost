//! DNS servers from whichever IPv6 configuration source is available (`ra` or `dhcpv6` feature).

use std::io;
use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, Instant};

use fqdn::FQDN;

use crate::ClientId;
use crate::custom::lookup_on_interface;

/// How long a lookup waits for the first DNS servers from any source.
const FIRST_SERVERS_TIMEOUT: Duration = Duration::from_secs(3);
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Configuration for [`Resolver::Ipv6`](crate::Resolver::Ipv6): DNS servers from DHCPv6 or Router
/// Advertisements on an interface, whichever is available, preferring DHCPv6.
///
/// Uses only the sources enabled at compile time: with just the `ra` feature this behaves like
/// [`RaResolverConfig`](crate::RaResolverConfig) (and ignores the [`ClientId`]); with just
/// `dhcpv6`, like [`Dhcpv6ResolverConfig`](crate::Dhcpv6ResolverConfig).
///
/// **Some networks require a particular DHCPv6 Client Identifier; see [`ClientId`].**
///
/// Clones share the same sources, which stop when the last clone is dropped. Only clones of
/// the same config compare equal.
#[cfg_attr(docsrs, doc(cfg(any(feature = "ra", feature = "dhcpv6"))))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ipv6ResolverConfig {
    interface: String,
    #[cfg(feature = "dhcpv6")]
    dhcpv6: Option<crate::Dhcpv6ResolverConfig>,
    #[cfg(feature = "ra")]
    ra: Option<crate::RaResolverConfig>,
}

impl Ipv6ResolverConfig {
    /// Starts every enabled source on `interface` right away. Fails only when none of them can
    /// start (e.g. without the privileges each needs; see the per-source configs), returning the
    /// last error. An invalid `client_id` is always an error.
    pub fn new(interface: impl Into<String>, client_id: ClientId) -> io::Result<Self> {
        let interface = interface.into();
        client_id.validate()?;
        let mut error = None;

        #[cfg(feature = "dhcpv6")]
        let dhcpv6 = crate::Dhcpv6ResolverConfig::new(interface.clone(), client_id)
            .map_err(|e| error = Some(e))
            .ok();
        #[cfg(feature = "ra")]
        let ra = crate::RaResolverConfig::new(interface.clone())
            .map_err(|e| error = Some(e))
            .ok();

        let config = Self {
            interface,
            #[cfg(feature = "dhcpv6")]
            dhcpv6,
            #[cfg(feature = "ra")]
            ra,
        };
        let started = config.sources().count();
        match (started, error) {
            (0, Some(e)) => Err(e),
            _ => Ok(config),
        }
    }

    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// The DHCPv6 source, if enabled and started.
    #[cfg(feature = "dhcpv6")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dhcpv6")))]
    pub fn dhcpv6(&self) -> Option<&crate::Dhcpv6ResolverConfig> {
        self.dhcpv6.as_ref()
    }

    /// The Router Advertisement source, if enabled and started.
    #[cfg(feature = "ra")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ra")))]
    pub fn ra(&self) -> Option<&crate::RaResolverConfig> {
        self.ra.as_ref()
    }

    /// Nameservers of each started source, in order of precedence.
    fn sources(&self) -> impl Iterator<Item = (&'static str, Vec<Ipv6Addr>)> + '_ {
        let dhcpv6 = {
            #[cfg(feature = "dhcpv6")]
            {
                self.dhcpv6.as_ref().map(|c| ("DHCPv6", c.nameservers()))
            }
            #[cfg(not(feature = "dhcpv6"))]
            {
                None
            }
        };
        let ra = {
            #[cfg(feature = "ra")]
            {
                self.ra
                    .as_ref()
                    .map(|c| ("router advertisements", c.nameservers()))
            }
            #[cfg(not(feature = "ra"))]
            {
                None
            }
        };
        dhcpv6.into_iter().chain(ra)
    }

    /// Current DNS servers: DHCPv6's if it has any, otherwise those from Router Advertisements.
    pub fn nameservers(&self) -> Vec<Ipv6Addr> {
        self.sources()
            .map(|(_, servers)| servers)
            .find(|servers| !servers.is_empty())
            .unwrap_or_default()
    }

    pub(crate) fn lookup(&self, fqdn: &FQDN) -> io::Result<Vec<IpAddr>> {
        // shortcut: polls instead of waiting on the sources' condvars; fine for a short startup wait.
        let deadline = Instant::now() + FIRST_SERVERS_TIMEOUT;
        loop {
            let servers = self.nameservers();
            if !servers.is_empty() || Instant::now() >= deadline {
                let source = if self.sources().count() > 1 {
                    "DHCPv6 or router advertisements"
                } else {
                    self.sources().next().map_or("IPv6", |(name, _)| name)
                };
                return lookup_on_interface(servers, &self.interface, fqdn, source);
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }
}
