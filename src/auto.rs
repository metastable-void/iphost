
use std::{ops::Deref, sync::mpsc::{channel, Receiver, Sender, TryRecvError}, time::Duration};

/// Spawn a background thread to do hostname resolutions automatically.
/// 
/// You can check the resolved values later after you started this.
#[derive(Debug, Clone)]
pub struct AutoIpHostResolver {
    inner: super::IpHostResolver,
    on_drop: Sender<()>,
}

impl AutoIpHostResolver {
    pub fn new(ip_host: super::IpHost, refresh_interval: Duration) -> Self {
        let (tx, rx) = channel();
        let me = Self {
            inner: super::IpHostResolver::new_with_config(ip_host, true, false),
            on_drop: tx,
        };

        me.start_worker(rx, refresh_interval);

        me
    }

    fn start_worker(&self, on_drop_receiver: Receiver<()>, interval: Duration) {
        let inner_clone = self.inner.clone();
        std::thread::spawn(move || {
            loop {
                match on_drop_receiver.try_recv() {
                    Ok(_) => break,
                    Err(TryRecvError::Disconnected) => break,
                    Err(_) => {},
                }
                #[allow(unused_variables)]
                let res = inner_clone.resolve();

                #[cfg(feature = "tracing")]
                for ip in res {
                    tracing::debug!(resolved_ip = %ip, "Hostname resolved");
                }

                std::thread::sleep(interval);
            }

            #[cfg(feature = "tracing")]
            tracing::info!("Consumer dropped. Exiting resolution thread.");
        });
    }
}

impl Drop for AutoIpHostResolver {
    fn drop(&mut self) {
        let _ = self.on_drop.send(());
    }
}

impl Deref for AutoIpHostResolver {
    type Target = crate::IpHostResolver;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
