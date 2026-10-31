//! DNS servers from stateless DHCPv6 (`dhcpv6` feature): Information-Request, RFC 8415 section 18.2.6.

use std::collections::BTreeMap;
use std::io;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, Weak, mpsc};
use std::time::{Duration, Instant};

use fqdn::FQDN;
use socket2::{Domain, Protocol, SockRef, Socket, Type};

use crate::ClientId;
use crate::custom::{
    DISCOVERY_TIMEOUT, bind_to_interface, if_index, lookup_on_interface, random_u32,
};
use crate::resolver::Lookup;

/// Also how often the thread notices that every config was dropped.
const RECV_TIMEOUT: Duration = Duration::from_secs(1);

const CLIENT_PORT: u16 = 546;
const SERVER_PORT: u16 = 547;
/// All_DHCP_Relay_Agents_and_Servers.
const ALL_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);

const MSG_REPLY: u8 = 7;
const MSG_INFORMATION_REQUEST: u8 = 11;
const OPTION_CLIENTID: u16 = 1;
const OPTION_ORO: u16 = 6;
const OPTION_ELAPSED_TIME: u16 = 8;
const OPTION_STATUS_CODE: u16 = 13;
const OPTION_DNS_SERVERS: u16 = 23;
const OPTION_INFORMATION_REFRESH_TIME: u16 = 32;

/// RFC 8415 section 7.6.
const INF_TIMEOUT: Duration = Duration::from_secs(1);
const INF_MAX_RT: Duration = Duration::from_secs(3600);
const IRT_DEFAULT: u32 = 86400;
const IRT_MINIMUM: u32 = 600;

/// Configuration for [`Resolver::Dhcpv6`](crate::Resolver::Dhcpv6): DNS servers from DHCPv6 on an interface.
///
/// **Some networks require a particular Client Identifier; see [`ClientId`].**
///
/// Clones share one client, which stops when the last clone is dropped.
#[cfg_attr(docsrs, doc(cfg(feature = "dhcpv6")))]
#[derive(Clone)]
pub struct Dhcpv6ResolverConfig {
    interface: String,
    client_id: ClientId,
    shared: Arc<Shared>,
}

impl std::fmt::Debug for Dhcpv6ResolverConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dhcpv6ResolverConfig")
            .field("interface", &self.interface)
            .field("client_id", &self.client_id)
            .field("nameservers", &self.nameservers())
            .finish()
    }
}

/// Equal only for clones of the same config, which share one client.
impl PartialEq for Dhcpv6ResolverConfig {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.shared, &other.shared)
    }
}

impl Eq for Dhcpv6ResolverConfig {}

impl std::hash::Hash for Dhcpv6ResolverConfig {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        Arc::as_ptr(&self.shared).hash(state);
    }
}

impl Dhcpv6ResolverConfig {
    /// Starts sending DHCPv6 Information-Requests on `interface` right away, and again
    /// whenever the server's information refresh time passes.
    ///
    /// `client_id` is required on purpose, because some networks only answer a particular one
    /// (e.g. NTT's NGN needs [`ClientId::DuidLl`] with the interface's MAC address); see [`ClientId`].
    ///
    /// All configs on the same interface in the same network namespace share one socket
    /// on UDP port 546, tied to that
    /// interface; any number of configs can use the same interface. Binding port 546 needs
    /// privileges on most platforms (e.g. `CAP_NET_BIND_SERVICE` on Linux). The socket is
    /// closed when the last config on the interface is dropped.
    /// Each client buffers at most 64 pending datagrams. A full client queue
    /// drops incoming datagrams without delaying other clients; normal DHCPv6
    /// retransmission still applies. Dropped clients release their queue and
    /// subscription without waiting for another packet.
    /// On Linux and Android, namespace identity uses `SO_NETNS_COOKIE`; older
    /// kernels without that option need readable `/proc/thread-self/ns/net`.
    ///
    /// Another DHCPv6 client on the host that is bound to the interface's address (e.g.
    /// systemd-networkd) receives the Replies instead, so this then gets no DNS servers.
    ///
    /// The interface does not need to exist yet.
    ///
    /// # Errors
    ///
    /// - `client_id` is a [`ClientId::Raw`] that is not 3 to 130 bytes long
    ///   ([`io::ErrorKind::InvalidInput`]).
    /// - No other config holds the socket on this interface and it cannot be opened, e.g.
    ///   without the privileges for port 546, or when another process holds that port.
    /// - A client thread cannot be spawned.
    /// - On Linux or Android, the namespace cannot be identified: a kernel
    ///   without `SO_NETNS_COOKIE` also has no readable `/proc/thread-self/ns/net`.
    pub fn new(interface: impl Into<String>, client_id: ClientId) -> io::Result<Self> {
        let interface = interface.into();
        client_id.validate()?;
        let client_id = client_id.resolve();
        let listener = Listener::get(&interface)?;
        // Subscribed before the first request, so no Reply is missed.
        let replies = listener.subscribe();

        let shared = Arc::new(Shared::default());
        let weak = Arc::downgrade(&shared);
        let thread_interface = interface.clone();
        std::thread::Builder::new()
            .name("iphost-dhcpv6".into())
            .spawn({
                let duid = client_id.duid();
                move || {
                    run(
                        &listener,
                        &replies,
                        &thread_interface,
                        duid.as_deref(),
                        &weak,
                    )
                }
            })?;
        Ok(Self {
            interface,
            client_id,
            shared,
        })
    }

    /// The interface DHCPv6 runs on, and lookups are bound to.
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// The Client Identifier sent. [`ClientId::RandomDuidLl`] shows up as the generated
    /// [`ClientId::DuidLl`].
    pub fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    /// DNS servers from the latest Reply. They stay in use after the refresh time until a new Reply arrives.
    pub fn nameservers(&self) -> Vec<Ipv6Addr> {
        self.shared.servers().clone().unwrap_or_default()
    }

    pub(crate) fn lookup(&self, fqdn: &FQDN) -> io::Result<Lookup> {
        let servers = {
            let servers = self.shared.servers();
            let (servers, _) = self
                .shared
                .cond
                .wait_timeout_while(servers, DISCOVERY_TIMEOUT, |s| s.is_none())
                .unwrap_or_else(PoisonError::into_inner);
            servers.clone().unwrap_or_default()
        };
        lookup_on_interface(servers, &self.interface, fqdn, "DHCPv6")
    }
}

#[derive(Debug, Default)]
struct Shared {
    /// `None` until the first Reply.
    servers: Mutex<Option<Vec<Ipv6Addr>>>,
    cond: Condvar,
}

#[cfg(test)]
pub(crate) fn test_config(servers: &[Ipv6Addr]) -> Dhcpv6ResolverConfig {
    Dhcpv6ResolverConfig {
        interface: "test-interface".into(),
        client_id: ClientId::None,
        shared: Arc::new(Shared {
            servers: Mutex::new(Some(servers.to_vec())),
            cond: Condvar::new(),
        }),
    }
}

impl Shared {
    fn servers(&self) -> MutexGuard<'_, Option<Vec<Ipv6Addr>>> {
        self.servers.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A datagram received on the listener's interface.
type Datagram = Vec<u8>;
const PENDING_CAPACITY: usize = 64;
type Clients = BTreeMap<u64, mpsc::SyncSender<Datagram>>;

struct Replies {
    listener: Arc<Listener>,
    id: u64,
    receiver: mpsc::Receiver<Datagram>,
}

impl std::ops::Deref for Replies {
    type Target = mpsc::Receiver<Datagram>;
    fn deref(&self) -> &Self::Target {
        &self.receiver
    }
}

impl Drop for Replies {
    fn drop(&mut self) {
        self.listener.clients().remove(&self.id);
    }
}

/// Whether tying a socket to an interface also limits what it receives to that interface.
const TIED_RECEIVE: bool = cfg!(any(
    target_os = "linux",
    target_vendor = "apple",
    target_os = "illumos",
    target_os = "solaris"
));

/// Whether a datagram from `src` arrived on the interface with `index` (`None`: absent), for
/// a socket tied to it if possible.
///
/// Where tying limits receiving, the kernel already ensures this. Elsewhere, a link-local
/// source's scope is the arrival interface. (Not usable on Linux: for an interface enslaved to
/// a VRF, the scope is the VRF device.)
fn arrived_on(src: SocketAddr, index: Option<u32>) -> bool {
    match src {
        SocketAddr::V6(src) if src.ip().is_unicast_link_local() => {
            (TIED_RECEIVE && index.is_some()) || index == Some(src.scope_id())
        }
        _ => true,
    }
}

/// The DHCPv6 client socket for one interface, shared by every client on it.
///
/// The kernel delivers each Reply to only one of the matching sockets on port 546, so clients
/// on the same interface share one socket. Every datagram goes to every client there, and each
/// keeps only Replies to its own transaction.
///
/// The socket is tied to the interface, so listeners on different interfaces never receive each
/// other's Replies, and Replies arrive even when the interface is enslaved to a Linux VRF
/// (no reliance on `udp_l3mdev_accept`). It is a wildcard socket, which the kernel only picks
/// when no socket is bound to the destination address, so it never takes Replies away from
/// another client bound to the link-local address (e.g. systemd-networkd).
struct Listener {
    namespace: Namespace,
    interface: String,
    /// The socket, and the interface index it is tied to (`None` while the interface is absent).
    socket: Mutex<(Arc<UdpSocket>, Option<u32>)>,
    clients: Mutex<Clients>,
}

/// Distinguishes equally named interfaces in separate network namespaces.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Namespace {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    Cookie(u64),
    #[cfg(any(target_os = "linux", target_os = "android"))]
    Inode(u64, u64),
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    Native,
}

type Interfaces = BTreeMap<String, Weak<Listener>>;
static LISTENERS: Mutex<BTreeMap<Namespace, Interfaces>> = Mutex::new(BTreeMap::new());

fn namespace() -> io::Result<Namespace> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::os::fd::AsRawFd;
        // Linux UAPI asm-generic/socket.h and arch/sparc/include/uapi/asm/socket.h.
        let option = if cfg!(any(target_arch = "sparc", target_arch = "sparc64")) {
            0x0050
        } else {
            71
        };
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        let mut cookie = 0u64;
        let mut length = std::mem::size_of_val(&cookie) as libc::socklen_t;
        // net/core/sock.c sock_getsockopt(SO_NETNS_COOKIE) returns the socket
        // namespace's u64 identity without procfs or privileges. The writable
        // buffer has exactly that size.
        if unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                (&mut cookie as *mut u64).cast(),
                &mut length,
            )
        } < 0
        {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ENOPROTOOPT) {
                return Err(error);
            }
            use std::os::unix::fs::MetadataExt;
            let namespace = std::fs::metadata("/proc/thread-self/ns/net")?;
            return Ok(Namespace::Inode(namespace.dev(), namespace.ino()));
        }
        Ok(Namespace::Cookie(cookie))
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    Ok(Namespace::Native)
}

/// A UDP socket on port 546, tied to `interface` if it exists.
fn open_socket(interface: &str) -> io::Result<(Arc<UdpSocket>, Option<u32>)> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(true)?;
    socket.set_reuse_address(true)?;
    let index = if_index(interface).ok();
    if index.is_some() {
        bind_to_interface(&SockRef::from(&socket), interface, true)?;
    }
    socket.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, CLIENT_PORT)).into())?;
    socket.set_read_timeout(Some(RECV_TIMEOUT))?;
    Ok((Arc::new(socket.into()), index))
}

impl Listener {
    /// The listener for `interface`, binding port 546 if no client there holds one yet.
    fn get(interface: &str) -> io::Result<Arc<Self>> {
        let namespace = namespace()?;
        let mut listeners = LISTENERS.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(listener) = listeners
            .get(&namespace)
            .and_then(|interfaces| interfaces.get(interface))
            .and_then(Weak::upgrade)
        {
            return Ok(listener);
        }

        let listener = Arc::new(Self {
            namespace,
            interface: interface.into(),
            socket: Mutex::new(open_socket(interface)?),
            clients: Mutex::default(),
        });
        let weak = Arc::downgrade(&listener);
        if let Err(error) = std::thread::Builder::new()
            .name("iphost-dhcpv6-rx".into())
            .spawn(move || Self::receive(&weak))
        {
            // Listener::drop takes this lock even if construction failed.
            drop(listeners);
            return Err(error);
        }
        listeners
            .entry(namespace)
            .or_default()
            .insert(interface.into(), Arc::downgrade(&listener));
        Ok(listener)
    }

    /// The socket, and the interface index it is tied to.
    fn current(&self) -> (Arc<UdpSocket>, Option<u32>) {
        self.socket
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Re-creates the socket when the interface appears, disappears, or is re-created.
    /// (Changing an existing device binding would need more privileges on Linux.)
    fn follow_interface(&self) {
        let index = if_index(&self.interface).ok();
        let mut socket = self.socket.lock().unwrap_or_else(PoisonError::into_inner);
        if socket.1 == index {
            return;
        }
        match open_socket(&self.interface) {
            Ok(new) => *socket = new,
            Err(_e) => {
                #[cfg(feature = "tracing")]
                tracing::warn!(error = %_e, interface = self.interface, "DHCPv6 socket re-creation failed");
            }
        }
    }

    fn clients(&self) -> MutexGuard<'_, Clients> {
        self.clients.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn subscribe(self: &Arc<Self>) -> Replies {
        let (tx, receiver) = mpsc::sync_channel(PENDING_CAPACITY);
        let mut clients = self.clients();
        let id = clients.last_key_value().map_or(0, |(id, _)| id + 1);
        clients.insert(id, tx);
        Replies {
            listener: self.clone(),
            id,
            receiver,
        }
    }

    fn publish(&self, bytes: &[u8]) {
        self.clients().retain(|_, tx| {
            matches!(
                tx.try_send(bytes.to_vec()),
                Ok(()) | Err(mpsc::TrySendError::Full(_))
            )
        });
    }

    /// Hands every datagram from the interface to every client, until no client holds the listener.
    fn receive(listener: &Weak<Self>) {
        let mut buf = [0u8; 65536];
        while let Some(listener) = listener.upgrade() {
            listener.follow_interface();
            let (socket, index) = listener.current();
            match socket.recv_from(&mut buf) {
                Ok((len, src)) if arrived_on(src, index) => listener.publish(&buf[..len]),
                Ok(_) => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Err(_e) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!(error = %_e, "DHCPv6 receive failed");
                    std::thread::sleep(RECV_TIMEOUT);
                }
            }
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let mut listeners = LISTENERS.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(interfaces) = listeners.get_mut(&self.namespace) {
            // A new listener may have replaced our expired weak reference.
            if interfaces
                .get(&self.interface)
                .is_some_and(|weak| std::ptr::eq(weak.as_ptr(), self))
            {
                interfaces.remove(&self.interface);
            }
            if interfaces.is_empty() {
                listeners.remove(&self.namespace);
            }
        }
    }
}

/// An Information-Request exchange in progress.
struct Exchange {
    xid: [u8; 3],
    started: Instant,
    rt: Duration,
}

/// `duration` times a random factor in [0.9, 1.1] (RFC 8415 section 15).
fn jitter(duration: Duration) -> Duration {
    duration.mul_f64(0.9 + 0.2 * f64::from(random_u32()) / f64::from(u32::MAX))
}

fn run(
    listener: &Listener,
    replies: &Replies,
    interface: &str,
    duid: Option<&[u8]>,
    shared: &Weak<Shared>,
) {
    let mut exchange: Option<Exchange> = None;
    let mut next_send = Instant::now();
    let mut bound_index = None;

    while let Some(shared) = shared.upgrade() {
        let (socket, index) = listener.current();
        if index != bound_index {
            // The interface appeared, vanished or was re-created: ask again right away.
            bound_index = index;
            exchange = None;
            next_send = Instant::now();
        }
        let now = Instant::now();
        if now >= next_send {
            let ex = exchange.get_or_insert_with(|| Exchange {
                xid: random_u32().to_be_bytes()[1..].try_into().unwrap(),
                started: now,
                rt: jitter(INF_TIMEOUT),
            });
            if let Err(_e) = send(&socket, interface, duid, ex, now) {
                #[cfg(feature = "tracing")]
                tracing::debug!(error = %_e, interface, "DHCPv6 Information-Request failed");
            }
            next_send = now + ex.rt;
            ex.rt = jitter((ex.rt * 2).min(INF_MAX_RT));
        }

        let timeout = next_send
            .saturating_duration_since(Instant::now())
            .clamp(Duration::from_millis(10), RECV_TIMEOUT);
        // Disconnection cannot happen while this thread holds the listener.
        let Ok(msg) = replies.recv_timeout(timeout) else {
            continue;
        };

        let Some(ex) = &exchange else { continue };
        let Some(reply) = parse_reply(&msg, ex.xid, duid) else {
            continue;
        };

        #[cfg(feature = "tracing")]
        tracing::debug!(?reply, interface, "DHCPv6 DNS servers");
        *shared.servers() = Some(reply.servers);
        shared.cond.notify_all();
        exchange = None;
        // 0xffffffff (infinity) becomes ~136 years.
        let refresh = Duration::from_secs(reply.refresh.max(IRT_MINIMUM).into());
        next_send = Instant::now()
            .checked_add(refresh)
            .unwrap_or(Instant::now() + INF_MAX_RT);
    }

    #[cfg(feature = "tracing")]
    tracing::debug!(interface, "DHCPv6 client stopped");
}

fn send(
    socket: &UdpSocket,
    interface: &str,
    duid: Option<&[u8]>,
    ex: &Exchange,
    now: Instant,
) -> io::Result<()> {
    let index = if_index(interface)?;
    SockRef::from(socket).set_multicast_if_v6(index)?;
    let elapsed = now.duration_since(ex.started).as_millis() / 10;
    let msg = information_request(ex.xid, duid, elapsed.min(0xffff) as u16);
    socket.send_to(&msg, SocketAddrV6::new(ALL_SERVERS, SERVER_PORT, 0, index))?;
    Ok(())
}

fn information_request(xid: [u8; 3], duid: Option<&[u8]>, elapsed_centis: u16) -> Vec<u8> {
    let mut msg = vec![MSG_INFORMATION_REQUEST];
    msg.extend(xid);
    let client_id = duid.map(|duid| (OPTION_CLIENTID, duid.to_vec()));
    for (code, data) in client_id.into_iter().chain([
        (OPTION_ELAPSED_TIME, elapsed_centis.to_be_bytes().to_vec()),
        (
            OPTION_ORO,
            [OPTION_DNS_SERVERS, OPTION_INFORMATION_REFRESH_TIME]
                .iter()
                .flat_map(|o| o.to_be_bytes())
                .collect(),
        ),
    ]) {
        msg.extend(code.to_be_bytes());
        msg.extend((data.len() as u16).to_be_bytes());
        msg.extend(data);
    }
    msg
}

#[derive(Debug, PartialEq, Eq)]
struct Reply {
    servers: Vec<Ipv6Addr>,
    /// Information refresh time in seconds.
    refresh: u32,
}

/// Parses a successful Reply to the exchange `xid`.
///
/// A Reply carrying a Client Identifier other than ours (`duid`) is for someone else. A missing
/// one is tolerated, though RFC 8415 requires servers to echo it.
fn parse_reply(msg: &[u8], xid: [u8; 3], duid: Option<&[u8]>) -> Option<Reply> {
    if msg.len() < 4 || msg[0] != MSG_REPLY || msg[1..4] != xid {
        return None;
    }
    let mut reply = Reply {
        servers: Vec::new(),
        refresh: IRT_DEFAULT,
    };
    let mut opts = &msg[4..];
    while !opts.is_empty() {
        let code = u16::from_be_bytes(opts.get(0..2)?.try_into().unwrap());
        let len = usize::from(u16::from_be_bytes(opts.get(2..4)?.try_into().unwrap()));
        let data = opts.get(4..4 + len)?;
        match code {
            OPTION_CLIENTID if duid.is_some_and(|duid| duid != data) => return None,
            OPTION_STATUS_CODE if data.get(0..2)? != [0, 0] => return None,
            OPTION_DNS_SERVERS if len % 16 == 0 => {
                reply.servers = data
                    .as_chunks::<16>()
                    .0
                    .iter()
                    .map(|a| Ipv6Addr::from(*a))
                    .collect();
            }
            OPTION_INFORMATION_REFRESH_TIME if len == 4 => {
                reply.refresh = u32::from_be_bytes(data.try_into().unwrap());
            }
            _ => {}
        }
        opts = &opts[4 + len..];
    }
    Some(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "isolated container with CAP_SYS_ADMIN and CAP_NET_RAW"]
    fn removed_subscriptions_do_not_wait_for_another_packet() {
        assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNET) }, 0);
        let listener = Listener::get("lo").unwrap();
        let survivor = listener.subscribe();
        for _ in 0..1000 {
            drop(listener.subscribe());
        }
        assert_eq!(
            listener.clients().len(),
            1,
            "closed subscribers are cached by history"
        );
        listener.publish(b"survivor");
        assert_eq!(
            survivor.recv_timeout(Duration::from_secs(1)).unwrap(),
            b"survivor"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "isolated container with CAP_SYS_ADMIN and CAP_NET_RAW"]
    fn stalled_subscriber_has_a_bounded_fifo() {
        assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNET) }, 0);
        let listener = Listener::get("lo").unwrap();
        let receiver = listener.subscribe();
        let active = listener.subscribe();
        for id in 0..1024u32 {
            listener.publish(&id.to_be_bytes());
            assert_eq!(
                active.recv_timeout(Duration::from_secs(1)).unwrap(),
                id.to_be_bytes()
            );
        }
        let received = receiver.try_iter().collect::<Vec<_>>();
        assert_eq!(
            received.len(),
            64,
            "a stalled subscriber retained the entire packet history"
        );
        for (id, packet) in received.iter().enumerate() {
            assert_eq!(*packet, (id as u32).to_be_bytes());
        }
        listener.publish(b"after draining");
        assert_eq!(
            receiver.recv_timeout(Duration::from_secs(1)).unwrap(),
            b"after draining"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "isolated container with CAP_SYS_ADMIN and CAP_NET_RAW"]
    fn completed_discovery_clients_release_subscriptions_while_another_stays() {
        assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNET) }, 0);
        let survivor = Dhcpv6ResolverConfig::new("lo", ClientId::None).unwrap();
        let listener = Listener::get("lo").unwrap();
        for epoch in 0..4 {
            let configs = (0..32)
                .map(|_| Dhcpv6ResolverConfig::new("lo", ClientId::None).unwrap())
                .collect::<Vec<_>>();
            let snapshots = configs
                .iter()
                .map(|config| Arc::downgrade(&config.shared))
                .collect::<Vec<_>>();
            drop(configs);
            let deadline = Instant::now() + Duration::from_secs(5);
            while listener.clients().len() != 1 && Instant::now() < deadline {
                std::thread::yield_now();
            }
            assert_eq!(listener.clients().len(), 1);
            assert!(
                snapshots
                    .iter()
                    .all(|snapshot| snapshot.strong_count() == 0)
            );
            assert!(survivor.nameservers().is_empty());
            eprintln!("DHCP_CLIENT_HISTORY epoch={epoch} removed=32 subscribers=1");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "isolated container with CAP_SYS_ADMIN and CAP_NET_RAW"]
    fn client_spawn_failure_removes_its_subscription() {
        assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNET) }, 0);
        let listener = Listener::get("lo").unwrap();
        refuse_syscalls(&[libc::SYS_clone, libc::SYS_clone3], libc::EAGAIN);
        for _ in 0..3 {
            let error = Dhcpv6ResolverConfig::new("lo", ClientId::None).unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EAGAIN));
            assert!(listener.clients().is_empty());
        }
    }

    #[cfg(target_os = "linux")]
    fn refuse_syscalls(syscalls: &[libc::c_long], errno: i32) {
        let mut filter = vec![libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 0,
        }];
        for syscall in syscalls {
            filter.push(libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 1,
                k: *syscall as u32,
            });
            filter.push(libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0x00050000 | errno as u32,
            });
        }
        filter.push(libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x7fff0000,
        });
        let program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_mut_ptr(),
        };
        // The kernel copies this filter; only this test thread and its children inherit it.
        unsafe {
            assert_eq!(
                libc::prctl(
                    libc::PR_SET_NO_NEW_PRIVS,
                    1 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong
                ),
                0
            );
            assert_eq!(
                libc::prctl(
                    libc::PR_SET_SECCOMP,
                    2 as libc::c_ulong,
                    &program as *const _,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong
                ),
                0
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "isolated container with CAP_SYS_ADMIN and CAP_NET_RAW"]
    fn receiver_spawn_failure_releases_cache_lock_and_socket() {
        assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNET) }, 0);
        let ns = namespace().unwrap();
        refuse_syscalls(&[libc::SYS_clone, libc::SYS_clone3], libc::EAGAIN);
        for _ in 0..3 {
            match Listener::get("lo") {
                Err(error) => assert_eq!(error.raw_os_error(), Some(libc::EAGAIN)),
                Ok(_) => panic!("receiver thread unexpectedly started"),
            }
            assert!(!LISTENERS.lock().unwrap().contains_key(&ns));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "isolated container with CAP_SYS_CHROOT and CAP_SYS_ADMIN"]
    fn namespace_cookie_needs_no_procfs() {
        let directory = std::env::temp_dir().join(format!("iphost-no-proc-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let root = std::ffi::CString::new(directory.as_os_str().as_encoded_bytes()).unwrap();
        std::thread::spawn(move || {
            // Isolate this thread's root and network namespace before chroot.
            assert_eq!(
                unsafe { libc::unshare(libc::CLONE_NEWNET | libc::CLONE_FS) },
                0
            );
            assert_eq!(unsafe { libc::chroot(root.as_ptr()) }, 0);
            std::env::set_current_dir("/").unwrap();
            assert!(!std::path::Path::new("/proc").exists());
            assert!(matches!(namespace().unwrap(), Namespace::Cookie(_)));
            let listener = Listener::get("lo").unwrap();
            assert!(Arc::ptr_eq(&listener, &Listener::get("lo").unwrap()));
        })
        .join()
        .unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "isolated container with CAP_SYS_ADMIN and CAP_NET_RAW"]
    fn unsupported_namespace_cookie_uses_namespace_inode() {
        let get = || {
            std::thread::spawn(|| {
                assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNET) }, 0);
                refuse_syscalls(&[libc::SYS_getsockopt], libc::ENOPROTOOPT);
                assert!(matches!(namespace().unwrap(), Namespace::Inode(_, _)));
                let listener = Listener::get("lo").unwrap();
                assert!(Arc::ptr_eq(&listener, &Listener::get("lo").unwrap()));
                listener
            })
            .join()
            .unwrap()
        };
        let first = get();
        let second = get();
        assert!(!Arc::ptr_eq(&first, &second));
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "isolated container with CAP_SYS_ADMIN and CAP_NET_RAW"]
    fn dropped_listeners_release_cache_records() {
        assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNET) }, 0);
        let listener = Listener::get("lo").unwrap();
        let weak = Arc::downgrade(&listener);
        drop(listener);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !LISTENERS.lock().unwrap().is_empty() && Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert_eq!(weak.strong_count(), 0);
        assert!(
            LISTENERS.lock().unwrap().is_empty(),
            "dead listener still occupies the global cache"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "isolated container with CAP_SYS_ADMIN and CAP_NET_RAW"]
    fn same_named_interfaces_share_only_within_their_network_namespace() {
        let get = || {
            std::thread::spawn(|| {
                // This test thread and its listener stay in their disposable netns.
                assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNET) }, 0);
                let listener = Listener::get("lo").unwrap();
                assert!(Arc::ptr_eq(&listener, &Listener::get("lo").unwrap()));
                listener
            })
            .join()
            .unwrap()
        };
        let first = get();
        let second = get();
        assert!(
            !Arc::ptr_eq(&first, &second),
            "reused another network namespace's DHCPv6 listener"
        );
    }

    const XID: [u8; 3] = [1, 2, 3];
    const DNS1: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x53);
    const DNS2: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x54);

    fn opt(code: u16, data: &[u8]) -> Vec<u8> {
        let mut o = code.to_be_bytes().to_vec();
        o.extend((data.len() as u16).to_be_bytes());
        o.extend(data);
        o
    }

    fn reply(opts: &[Vec<u8>]) -> Vec<u8> {
        let mut msg = vec![MSG_REPLY, 1, 2, 3];
        for o in opts {
            msg.extend(o);
        }
        msg
    }

    const DUID: [u8; 10] = [0, 3, 0, 1, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

    #[test]
    fn builds_information_request() {
        assert_eq!(
            information_request(XID, None, 0x0102),
            [11, 1, 2, 3, 0, 8, 0, 2, 1, 2, 0, 6, 0, 4, 0, 23, 0, 32]
        );
        let msg = information_request(XID, Some(&DUID), 0);
        assert_eq!(msg[4..18], [&[0, 1, 0, 10][..], &DUID].concat());
    }

    #[test]
    fn rejects_bad_raw_duid_lengths() {
        for len in [0, 2, 131] {
            let err = Dhcpv6ResolverConfig::new("lo", ClientId::Raw(vec![0; len])).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "length {len}");
        }
    }

    #[test]
    fn checks_reply_client_id() {
        let msg = reply(&[opt(OPTION_CLIENTID, &DUID)]);
        assert!(parse_reply(&msg, XID, Some(&DUID)).is_some());
        assert!(parse_reply(&msg, XID, None).is_some());
        let mut other = DUID;
        other[9] ^= 1;
        assert_eq!(parse_reply(&msg, XID, Some(&other)), None);
        // Tolerated: servers that do not echo it.
        assert!(parse_reply(&reply(&[]), XID, Some(&DUID)).is_some());
    }

    #[test]
    fn parses_reply() {
        let dns: Vec<u8> = [DNS1, DNS2].iter().flat_map(|a| a.octets()).collect();
        let msg = reply(&[
            opt(2, &[0; 10]), // Server Identifier
            opt(OPTION_DNS_SERVERS, &dns),
            opt(OPTION_INFORMATION_REFRESH_TIME, &3600u32.to_be_bytes()),
        ]);
        assert_eq!(
            parse_reply(&msg, XID, None),
            Some(Reply {
                servers: vec![DNS1, DNS2],
                refresh: 3600
            })
        );
        assert_eq!(parse_reply(&msg, [1, 2, 4], None), None);
        assert_eq!(
            parse_reply(&reply(&[]), XID, None),
            Some(Reply {
                servers: vec![],
                refresh: IRT_DEFAULT
            })
        );
    }

    #[test]
    fn rejects_failures_and_garbage() {
        assert_eq!(
            parse_reply(&reply(&[opt(OPTION_STATUS_CODE, &[0, 1])]), XID, None),
            None
        );
        assert!(parse_reply(&reply(&[opt(OPTION_STATUS_CODE, &[0, 0])]), XID, None).is_some());
        assert_eq!(
            parse_reply(&[MSG_REPLY, 1, 2, 3, 0, 23, 0, 16, 0], XID, None),
            None
        );
        assert_eq!(
            parse_reply(&[MSG_INFORMATION_REQUEST, 1, 2, 3], XID, None),
            None
        );
    }

    #[test]
    fn arrival_interface() {
        let ll =
            |scope| SocketAddr::V6(SocketAddrV6::new("fe80::1".parse().unwrap(), 547, 0, scope));
        let global: SocketAddr = "[2001:db8::1]:547".parse().unwrap();
        assert!(arrived_on(global, None));
        assert!(arrived_on(ll(7), Some(7)));
        assert!(!arrived_on(ll(7), None));
        // A VRF device as the scope: trusted only where the tied socket already filters.
        assert_eq!(arrived_on(ll(9), Some(7)), TIED_RECEIVE);
    }

    #[test]
    fn jitter_bounds() {
        for _ in 0..100 {
            let d = jitter(Duration::from_secs(10));
            assert!(d >= Duration::from_secs(9) && d <= Duration::from_secs(11));
        }
    }
}
