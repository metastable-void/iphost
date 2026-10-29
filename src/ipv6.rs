//! DNS servers from whichever IPv6 configuration source is available (`ra` or `dhcpv6` feature).

use std::io;
use std::net::Ipv6Addr;
use std::time::{Duration, Instant};

use fqdn::FQDN;

use crate::ClientId;
use crate::custom::{self, DISCOVERY_TIMEOUT, discovered_config, lookup_sources};
use crate::resolver::Lookup;

const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Configuration for [`Resolver::Ipv6`](crate::Resolver::Ipv6): DNS servers from DHCPv6 or Router
/// Advertisements on an interface, whichever is available, preferring DHCPv6.
/// By default, a nonempty DHCPv6 list is used exclusively. Enable
/// [`with_failure_fallback`](Self::with_failure_fallback) to try RA after DNS failures.
///
/// Uses only the sources enabled at compile time: with just the `ra` feature this behaves like
/// `RaResolverConfig` (and ignores the [`ClientId`]); with just
/// `dhcpv6`, like `Dhcpv6ResolverConfig`.
///
/// **Some networks require a particular DHCPv6 Client Identifier; see [`ClientId`].**
///
/// Clones share the same sources, which stop when the last clone is dropped. Only clones of
/// the same config with the same failure-fallback policy compare equal.
#[cfg_attr(docsrs, doc(cfg(any(feature = "ra", feature = "dhcpv6"))))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ipv6ResolverConfig {
    interface: String,
    failure_fallback: bool,
    #[cfg(feature = "dhcpv6")]
    dhcpv6: Option<crate::Dhcpv6ResolverConfig>,
    #[cfg(feature = "ra")]
    ra: Option<crate::RaResolverConfig>,
}

impl Ipv6ResolverConfig {
    /// Starts every enabled source on `interface` right away. A source that cannot start is
    /// left out, and not retried later.
    ///
    /// # Errors
    ///
    /// - `client_id` is invalid, as for
    ///   `Dhcpv6ResolverConfig::new`, even when only `ra`
    ///   is enabled.
    /// - None of the sources can start (e.g. without the privileges each needs; see the
    ///   per-source configs). The error is the last source's: RA's when both are enabled.
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
            failure_fallback: false,
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

    /// The interface the sources run on, and lookups are bound to.
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Enables per-family fallback to RA after the DHCPv6 servers exhaust their retries.
    /// Defaults to `false`. Positive answers, NXDOMAIN and NOERROR/NODATA are final for
    /// that family. Each lookup starts with DHCPv6 again and waits for discovery only once.
    ///
    /// At most three servers per source are queried. With both sources started this raises
    /// [`Resolver::max_lookup_time`](crate::Resolver::max_lookup_time) from 33 to 63 seconds.
    /// With one source the bound stays 33 seconds. Clones share discovery state but may
    /// select different policies with this builder; differing policies compare unequal.
    pub fn with_failure_fallback(mut self, enabled: bool) -> Self {
        self.failure_fallback = enabled;
        self
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
    /// A lookup with failure fallback enabled can subsequently consult RA's servers too.
    pub fn nameservers(&self) -> Vec<Ipv6Addr> {
        self.sources()
            .map(|(_, servers)| servers)
            .find(|servers| !servers.is_empty())
            .unwrap_or_default()
    }

    pub(crate) fn lookup(&self, fqdn: &FQDN) -> io::Result<Lookup> {
        let sources = wait_for_sources(
            || self.sources().map(|(_, servers)| servers).collect(),
            Instant::now,
            std::thread::sleep,
        );
        let configs = selected_configs(sources, &self.interface, self.failure_fallback);
        lookup_sources(&configs, fqdn)
    }

    pub(crate) fn max_lookup_time(&self) -> Duration {
        let sources = if self.failure_fallback {
            self.sources().count().max(1)
        } else {
            1
        };
        DISCOVERY_TIMEOUT + custom::query_time_bound(custom::MAX_SERVERS) * sources as u32
    }
}

fn selected_configs(
    sources: Vec<Vec<Ipv6Addr>>,
    interface: &str,
    fallback: bool,
) -> Vec<crate::StaticResolverConfig> {
    sources
        .into_iter()
        .filter(|s| !s.is_empty())
        .take(if fallback { 2 } else { 1 })
        .map(|s| discovered_config(s, interface))
        .collect()
}

fn wait_for_sources(
    mut sources: impl FnMut() -> Vec<Vec<Ipv6Addr>>,
    now: impl Fn() -> Instant,
    sleep: impl Fn(Duration),
) -> Vec<Vec<Ipv6Addr>> {
    // shortcut: polls instead of waiting on the sources' condvars; fine for a short startup wait.
    let deadline = now() + DISCOVERY_TIMEOUT;
    loop {
        let lists = sources();
        if lists.iter().any(|s| !s.is_empty()) || now() >= deadline {
            return lists;
        }
        sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(now())));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    fn config() -> Ipv6ResolverConfig {
        Ipv6ResolverConfig {
            interface: "test-interface".into(),
            failure_fallback: false,
            #[cfg(feature = "dhcpv6")]
            dhcpv6: Some(crate::dhcpv6::test_config(&["fe80::1".parse().unwrap()])),
            #[cfg(feature = "ra")]
            ra: Some(crate::ra::test_config(&["fe80::2".parse().unwrap()])),
        }
    }

    #[test]
    fn policy_clones_and_bounds() {
        let original = config();
        let clone = original.clone();
        assert_eq!(original, clone);
        let hash = |c: &Ipv6ResolverConfig| {
            let mut h = DefaultHasher::new();
            c.hash(&mut h);
            h.finish()
        };
        assert_eq!(hash(&original), hash(&clone));
        let fallback = clone.with_failure_fallback(true);
        assert_ne!(original, fallback);
        assert_eq!(original.nameservers(), fallback.nameservers());
        assert_eq!(original, fallback.clone().with_failure_fallback(false));
        assert_eq!(original.max_lookup_time(), Duration::from_secs(33));
        let seconds = if cfg!(all(feature = "ra", feature = "dhcpv6")) {
            63
        } else {
            33
        };
        assert_eq!(
            crate::Resolver::Ipv6(fallback).max_lookup_time(),
            Some(Duration::from_secs(seconds))
        );
        #[cfg(feature = "dhcpv6")]
        assert_eq!(
            original.nameservers(),
            vec!["fe80::1".parse::<Ipv6Addr>().unwrap()]
        );
        #[cfg(all(feature = "ra", not(feature = "dhcpv6")))]
        assert_eq!(
            original.nameservers(),
            vec!["fe80::2".parse::<Ipv6Addr>().unwrap()]
        );
    }

    #[cfg(all(feature = "ra", feature = "dhcpv6"))]
    #[test]
    fn unavailable_or_empty_source() {
        let mut config = config().with_failure_fallback(true);
        config.dhcpv6 = None;
        assert_eq!(config.max_lookup_time(), Duration::from_secs(33));
        assert_eq!(config.nameservers(), config.ra().unwrap().nameservers());
        config.dhcpv6 = Some(crate::dhcpv6::test_config(&[]));
        assert_eq!(config.nameservers(), config.ra().unwrap().nameservers());
        assert_eq!(config.max_lookup_time(), Duration::from_secs(63));
        config.ra = None;
        assert_eq!(config.max_lookup_time(), Duration::from_secs(33));
        assert!(config.nameservers().is_empty());
    }

    #[test]
    fn selection_and_interface_are_preserved_for_both_sources() {
        let lists = vec![
            vec!["fe80::1".parse().unwrap(); 5],
            vec!["fe80::2".parse().unwrap(); 4],
        ];
        let legacy = selected_configs(lists.clone(), "test-interface", false);
        assert_eq!(legacy.len(), 1);
        let fallback = selected_configs(lists.clone(), "test-interface", true);
        assert_eq!(fallback.len(), 2);
        assert_eq!(legacy[0], fallback[0]);
        for config in fallback {
            assert_eq!(config.nameservers().len(), custom::MAX_SERVERS);
            assert_eq!(
                config.bind_device(),
                Some(&crate::BindDevice::Interface("test-interface".into()))
            );
        }
        let ra_only = selected_configs(vec![vec![], lists[1].clone()], "test-interface", false);
        assert_eq!(ra_only.len(), 1);
        assert_eq!(
            ra_only[0].nameservers()[0].ip(),
            std::net::IpAddr::V6(lists[1][0])
        );
    }

    #[test]
    fn discovery_waits_once_and_snapshots_both_sources() {
        let start = Instant::now();
        let now = Cell::new(start);
        let lists = wait_for_sources(
            || vec![vec![], vec![]],
            || now.get(),
            |d| now.set(now.get() + d),
        );
        assert_eq!(now.get() - start, DISCOVERY_TIMEOUT);
        assert!(selected_configs(lists, "test-interface", true).is_empty());
        now.set(start);
        let discovered = "fe80::2".parse().unwrap();
        let lists = wait_for_sources(
            || {
                vec![
                    vec![],
                    if now.get() - start >= Duration::from_secs(1) {
                        vec![discovered]
                    } else {
                        vec![]
                    },
                ]
            },
            || now.get(),
            |d| now.set(now.get() + d),
        );
        assert_eq!(now.get() - start, Duration::from_secs(1));
        assert_eq!(lists, vec![vec![], vec![discovered]]);
    }
}
