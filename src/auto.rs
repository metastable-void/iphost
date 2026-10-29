use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::mpsc;
use std::time::Duration;

#[cfg(feature = "broadcast")]
use tokio::sync::broadcast;

use crate::{IpHost, IpHostResolver, Resolver};

/// Changes to the stored addresses. `None` means unchanged; `Some(None)` means the address was removed.
#[cfg(feature = "broadcast")]
#[cfg_attr(docsrs, doc(cfg(feature = "broadcast")))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpChanges {
    v4_change: Option<Option<Ipv4Addr>>,
    v6_change: Option<Option<Ipv6Addr>>,
}

#[cfg(feature = "broadcast")]
#[cfg_attr(docsrs, doc(cfg(feature = "broadcast")))]
impl IpChanges {
    /// Whether neither address changed.
    pub fn is_none(&self) -> bool {
        self.v4_change.is_none() && self.v6_change.is_none()
    }

    /// Whether at least one address changed.
    pub fn is_some(&self) -> bool {
        !self.is_none()
    }

    /// The new IPv4 address: `None` if unchanged, `Some(None)` if removed.
    pub fn v4_change(&self) -> Option<Option<Ipv4Addr>> {
        self.v4_change
    }

    /// The new IPv6 address: `None` if unchanged, `Some(None)` if removed.
    pub fn v6_change(&self) -> Option<Option<Ipv6Addr>> {
        self.v6_change
    }
}

/// Spawn a background thread to do hostname resolutions automatically.
///
/// You can check the resolved values later after you started this.
/// Dropping the last clone signals the thread to exit after its current lookup returns.
/// Drop does not wait for that thread. A system lookup inside libc has no bounded duration
/// and cannot be cancelled by dropping this resolver, timing out a caller's wait, or replacing
/// the hostname. Obsolete results cannot update the new hostname's cache.
#[derive(Debug, Clone)]
pub struct AutoIpHostResolver {
    inner: IpHostResolver,
    /// Never sent on; the worker exits when every clone of this is dropped.
    _shutdown: mpsc::Sender<()>,

    #[cfg(feature = "broadcast")]
    bc_pub: broadcast::Sender<IpChanges>,
}

impl AutoIpHostResolver {
    /// Starts resolving `ip_host` every `refresh_interval`, with the default [`IpHostResolver`] configuration.
    pub fn new(ip_host: IpHost, refresh_interval: Duration) -> Self {
        Self::from_resolver(IpHostResolver::new(ip_host), refresh_interval)
    }

    /// Starts resolving with a preconfigured [`IpHostResolver`] every `refresh_interval`.
    pub fn from_resolver(inner: IpHostResolver, refresh_interval: Duration) -> Self {
        let (shutdown, shutdown_rx) = mpsc::channel();

        #[cfg(feature = "broadcast")]
        let (bc_pub, _) = broadcast::channel(16);

        let worker = Worker {
            inner: inner.clone(),
            shutdown_rx,
            interval: refresh_interval,
            #[cfg(feature = "broadcast")]
            bc_pub: bc_pub.clone(),
        };
        std::thread::spawn(move || worker.run());

        Self {
            inner,
            _shutdown: shutdown,
            #[cfg(feature = "broadcast")]
            bc_pub,
        }
    }

    /// The IPv4 address from the latest resolution; see [`IpHostResolver::ipv4_addr`].
    pub fn ipv4_addr(&self) -> Option<Ipv4Addr> {
        self.inner.ipv4_addr()
    }

    /// The IPv6 address from the latest resolution; see [`IpHostResolver::ipv6_addr`].
    pub fn ipv6_addr(&self) -> Option<Ipv6Addr> {
        self.inner.ipv6_addr()
    }

    /// The current hostname.
    pub fn ip_host(&self) -> IpHost {
        self.inner.ip_host()
    }

    /// Replaces the hostname, returning the old one; see [`IpHostResolver::replace_ip_host`].
    ///
    /// The new hostname is first resolved on the next refresh, after any current lookup
    /// finishes and `refresh_interval` elapses.
    pub fn replace_ip_host(&self, ip_host: IpHost) -> IpHost {
        self.inner.replace_ip_host(ip_host)
    }

    /// The current DNS resolver.
    pub fn resolver(&self) -> Resolver {
        self.inner.resolver()
    }

    /// Replaces the DNS resolver, returning the old one; see [`IpHostResolver::set_resolver`].
    ///
    /// The new resolver is first used on the next refresh, after any current lookup
    /// finishes and `refresh_interval` elapses.
    pub fn set_resolver(&self, resolver: Resolver) -> Resolver {
        self.inner.set_resolver(resolver)
    }

    /// Subscribes to address changes from now on.
    #[cfg(feature = "broadcast")]
    #[cfg_attr(docsrs, doc(cfg(feature = "broadcast")))]
    pub fn subscribe_changes(&self) -> IpHostSubscriber {
        IpHostSubscriber {
            rx: self.bc_pub.subscribe(),
        }
    }
}

struct Worker {
    inner: IpHostResolver,
    shutdown_rx: mpsc::Receiver<()>,
    interval: Duration,
    #[cfg(feature = "broadcast")]
    bc_pub: broadcast::Sender<IpChanges>,
}

impl Worker {
    fn run(self) {
        let mut v4_addr = None;
        let mut v6_addr = None;

        loop {
            #[allow(unused_variables)]
            let res = self.inner.resolve();

            #[cfg(feature = "tracing")]
            for ip in res {
                tracing::trace!(resolved_ip = %ip, "Hostname resolved");
            }

            let new_v4_addr = self.inner.ipv4_addr();
            let v4_change = (new_v4_addr != v4_addr).then_some(new_v4_addr);
            v4_addr = new_v4_addr;

            let new_v6_addr = self.inner.ipv6_addr();
            let v6_change = (new_v6_addr != v6_addr).then_some(new_v6_addr);
            v6_addr = new_v6_addr;

            #[cfg(feature = "tracing")]
            {
                if let Some(v4) = v4_change {
                    tracing::debug!(ipv4 = ?v4, "IP address change");
                }
                if let Some(v6) = v6_change {
                    tracing::debug!(ipv6 = ?v6, "IP address change");
                }
            }

            #[cfg(feature = "broadcast")]
            if v4_change.is_some() || v6_change.is_some() {
                // Err only means there are no subscribers right now.
                let _ = self.bc_pub.send(IpChanges {
                    v4_change,
                    v6_change,
                });
            }
            #[cfg(not(feature = "broadcast"))]
            let _ = (v4_change, v6_change);

            match self.shutdown_rx.recv_timeout(self.interval) {
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                _ => break,
            }
        }

        #[cfg(feature = "tracing")]
        tracing::info!("Consumer dropped. Exiting resolution thread.");
    }
}

/// Subscriber to IP address changes.
#[cfg(feature = "broadcast")]
#[cfg_attr(docsrs, doc(cfg(feature = "broadcast")))]
#[derive(Debug)]
pub struct IpHostSubscriber {
    rx: broadcast::Receiver<IpChanges>,
}

#[cfg(feature = "broadcast")]
#[cfg_attr(docsrs, doc(cfg(feature = "broadcast")))]
impl IpHostSubscriber {
    /// Wait for next IP address changes, blocking the current thread.
    ///
    /// Changes that happen between calls are not lost (up to a small buffer).
    /// Returns None once the resolver is dropped.
    ///
    /// This MUST NOT be called from an async task directly; use `tokio::task::spawn_blocking()`.
    pub fn wait_for_change_blocking(&mut self) -> Option<IpChanges> {
        loop {
            match self.rx.blocking_recv() {
                Ok(v) => return Some(v),
                Err(broadcast::error::RecvError::Closed) => return None,
                Err(broadcast::error::RecvError::Lagged(_n)) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!("Event receiver lagged too much, discarding {} messages", _n);
                }
            }
        }
    }
}

#[cfg(all(test, feature = "broadcast"))]
mod tests {
    use super::*;

    #[test]
    fn subscriber_closes_after_drop() {
        let resolver = AutoIpHostResolver::new(
            IpHost::V4Addr(Ipv4Addr::LOCALHOST),
            Duration::from_millis(10),
        );
        let mut sub = resolver.subscribe_changes();
        drop(resolver);
        // Drains any initial change, then sees the channel close once the worker exits.
        while sub.wait_for_change_blocking().is_some() {}
    }

    #[test]
    fn wait_works_inside_spawn_blocking() {
        let rt = tokio::runtime::Builder::new_multi_thread().build().unwrap();
        rt.block_on(async {
            let resolver = AutoIpHostResolver::new(
                IpHost::V4Addr(Ipv4Addr::LOCALHOST),
                Duration::from_millis(10),
            );
            let mut sub = resolver.subscribe_changes();
            resolver.replace_ip_host(IpHost::V4Addr(Ipv4Addr::new(192, 0, 2, 1)));
            let change = tokio::task::spawn_blocking(move || sub.wait_for_change_blocking())
                .await
                .unwrap();
            assert!(change.is_some());
        });
    }
}
