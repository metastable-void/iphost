use std::{
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use dropcatch::DropCatcher;

#[cfg(feature = "broadcast")]
use tokio::sync::{broadcast, oneshot};

#[cfg(not(feature = "broadcast"))]
use std::sync::mpsc;

#[cfg(feature = "broadcast")]
#[cfg_attr(docsrs, doc(cfg(feature = "broadcast")))]
#[derive(Clone, Copy, Debug)]
pub struct IpChanges {
    v4_change: Option<Option<Ipv4Addr>>,
    v6_change: Option<Option<Ipv6Addr>>,
}

#[cfg(feature = "broadcast")]
#[cfg_attr(docsrs, doc(cfg(feature = "broadcast")))]
impl IpChanges {
    fn new(v4_change: Option<Option<Ipv4Addr>>, v6_change: Option<Option<Ipv6Addr>>) -> Self {
        Self {
            v4_change,
            v6_change,
        }
    }

    pub fn is_none(&self) -> bool {
        self.v4_change.is_none() && self.v6_change.is_none()
    }

    pub fn is_some(&self) -> bool {
        !self.is_none()
    }

    pub fn v4_change(&self) -> Option<Option<Ipv4Addr>> {
        self.v4_change
    }

    pub fn v6_change(&self) -> Option<Option<Ipv6Addr>> {
        self.v6_change
    }
}

/// Spawn a background thread to do hostname resolutions automatically.
///
/// You can check the resolved values later after you started this.
#[derive(Debug, Clone)]
pub struct AutoIpHostResolver {
    inner: super::IpHostResolver,
    _on_drop: DropCatcher,

    #[cfg(feature = "broadcast")]
    bc_pub: broadcast::Sender<IpChanges>,
}

impl AutoIpHostResolver {
    pub fn ipv4_addr(&self) -> Option<Ipv4Addr> {
        self.inner.ipv4_addr()
    }

    pub fn ipv6_addr(&self) -> Option<Ipv6Addr> {
        self.inner.ipv6_addr()
    }

    pub fn replace_ip_host(&self, ip_host: super::IpHost) -> Result<super::IpHost, super::IpHost> {
        self.inner.replace_ip_host(ip_host)
    }

    pub fn new(ip_host: super::IpHost, refresh_interval: Duration) -> Self {
        #[cfg(not(feature = "broadcast"))]
        let (tx, rx) = mpsc::channel();

        #[cfg(feature = "broadcast")]
        let (tx, rx) = oneshot::channel();

        #[cfg(feature = "broadcast")]
        let (bc_pub, _) = broadcast::channel(16);

        let on_drop = DropCatcher::new(move || {
            if let Err(_) = tx.send(()) {
                #[cfg(feature = "tracing")]
                tracing::warn!("Worker thread exited for some reason, before me");
            };
        });

        #[cfg(feature = "broadcast")]
        let bc_pub_clone = bc_pub.clone();

        let me = Self {
            inner: super::IpHostResolver::new_with_config(ip_host, true, false),
            _on_drop: on_drop,

            #[cfg(feature = "broadcast")]
            bc_pub: bc_pub_clone,
        };

        me.start_worker(
            rx,
            refresh_interval,
            #[cfg(feature = "broadcast")]
            bc_pub,
        );

        me
    }

    fn start_worker(
        &self,

        #[cfg(not(feature = "broadcast"))] on_drop_receiver: mpsc::Receiver<()>,

        #[cfg(feature = "broadcast")] mut on_drop_receiver: oneshot::Receiver<()>,

        interval: Duration,

        #[cfg(feature = "broadcast")] bc_pub: broadcast::Sender<IpChanges>,
    ) {
        let inner_clone = self.inner.clone();
        std::thread::spawn(move || {
            #[cfg(feature = "broadcast")]
            let mut ipv4_addr = None;

            #[cfg(feature = "broadcast")]
            let mut ipv6_addr = None;

            loop {
                #[cfg(feature = "broadcast")]
                match on_drop_receiver.try_recv() {
                    Ok(_) => break,
                    Err(oneshot::error::TryRecvError::Closed) => break,
                    Err(_) => {}
                }

                #[cfg(not(feature = "broadcast"))]
                match on_drop_receiver.try_recv() {
                    Ok(_) => break,
                    Err(mpsc::TryRecvError::Disconnected) => break,
                    Err(_) => {}
                }

                #[allow(unused_variables)]
                let res = inner_clone.resolve();

                #[cfg(feature = "tracing")]
                for ip in res {
                    tracing::trace!(resolved_ip = %ip, "Hostname resolved");
                }

                #[cfg(feature = "broadcast")]
                {
                    let new_v4_addr = inner_clone.ipv4_addr();
                    let v4_changed;
                    if new_v4_addr != ipv4_addr {
                        v4_changed = true;
                        ipv4_addr = new_v4_addr;
                    } else {
                        v4_changed = false;
                    }

                    let new_v6_addr = inner_clone.ipv6_addr();
                    let v6_changed;
                    if new_v6_addr != ipv6_addr {
                        v6_changed = true;
                        ipv6_addr = new_v6_addr;
                    } else {
                        v6_changed = false;
                    }

                    #[cfg(feature = "tracing")]
                    {
                        if v4_changed {
                            if let Some(v4) = ipv4_addr {
                                tracing::debug!(ipv4 = %v4, "IP address change");
                            } else {
                                tracing::debug!(ipv4 = %"(none)", "IP address change");
                            }
                        }
                        if v6_changed {
                            if let Some(v6) = ipv6_addr {
                                tracing::debug!(ipv6 = %v6, "IP address change");
                            } else {
                                tracing::debug!(ipv6 = %"(none)", "IP address change");
                            }
                        }
                    }

                    let change = match (v4_changed, v6_changed) {
                        (true, true) => IpChanges::new(Some(ipv4_addr), Some(ipv6_addr)),
                        (true, false) => IpChanges::new(Some(ipv4_addr), None),
                        (false, true) => IpChanges::new(None, Some(ipv6_addr)),
                        _ => IpChanges::new(None, None),
                    };

                    if change.is_some() {
                        let _ = bc_pub.send(change);
                    }
                }

                std::thread::sleep(interval);
            }

            #[cfg(feature = "tracing")]
            tracing::info!("Consumer dropped. Exiting resolution thread.");
        });
    }

    #[cfg(feature = "broadcast")]
    #[cfg_attr(docsrs, doc(cfg(feature = "broadcast")))]
    pub fn subscribe_changes(&self) -> IpHostSubscriber {
        IpHostSubscriber {
            tx: self.bc_pub.clone(),
        }
    }
}

#[cfg(feature = "broadcast")]
#[cfg_attr(docsrs, doc(cfg(feature = "broadcast")))]
pub struct IpHostSubscriber {
    tx: broadcast::Sender<IpChanges>,
}

#[cfg(feature = "broadcast")]
#[cfg_attr(docsrs, doc(cfg(feature = "broadcast")))]
impl IpHostSubscriber {
    /// Wait for next IP address changes, blocking the current thread.
    ///
    /// This function is safe to be called from an async context, like `tokio::task::spawn_blocking()`.
    pub fn wait_for_change_blocking(&self) -> Option<IpChanges> {
        loop {
            let mut rx = self.tx.subscribe();

            // We spawn a thread to make a call from an async context possible
            // (i.e. tokio::task::spawn_blocking()).
            let join = std::thread::spawn(move || rx.blocking_recv()).join();
            let res = match join {
                Ok(v) => v,
                _ => {
                    #[cfg(feature = "tracing")]
                    tracing::error!("Event receiver thread panicked");
                    continue;
                }
            };

            #[allow(unreachable_patterns)]
            let val = match res {
                Err(broadcast::error::RecvError::Closed) => None,
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!("Event receiver lagged too much, discarding {} messages", n);
                    continue;
                }
                Ok(v) => Some(v),
                _ => None,
            };

            return val;
        }
    }
}
