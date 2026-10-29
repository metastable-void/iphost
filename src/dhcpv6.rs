//! DNS servers from stateless DHCPv6 (`dhcpv6` feature): Information-Request, RFC 8415 section 18.2.6.

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
    /// All configs on the same interface share one socket on UDP port 546, tied to that
    /// interface; any number of configs can use the same interface. Binding port 546 needs
    /// privileges on most platforms (e.g. `CAP_NET_BIND_SERVICE` on Linux). The socket is
    /// closed when the last config on the interface is dropped.
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
    interface: String,
    /// The socket, and the interface index it is tied to (`None` while the interface is absent).
    socket: Mutex<(Arc<UdpSocket>, Option<u32>)>,
    clients: Mutex<Vec<mpsc::Sender<Datagram>>>,
}

/// Per interface, held strongly only by clients (and briefly by the receive thread).
static LISTENERS: Mutex<Vec<(String, Weak<Listener>)>> = Mutex::new(Vec::new());

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
        let mut listeners = LISTENERS.lock().unwrap_or_else(PoisonError::into_inner);
        listeners.retain(|(_, weak)| weak.strong_count() > 0);
        if let Some(listener) = listeners
            .iter()
            .find(|(name, _)| name == interface)
            .and_then(|(_, weak)| weak.upgrade())
        {
            return Ok(listener);
        }

        let listener = Arc::new(Self {
            interface: interface.into(),
            socket: Mutex::new(open_socket(interface)?),
            clients: Mutex::default(),
        });
        let weak = Arc::downgrade(&listener);
        std::thread::Builder::new()
            .name("iphost-dhcpv6-rx".into())
            .spawn(move || Self::receive(&weak))?;
        listeners.push((interface.into(), Arc::downgrade(&listener)));
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

    fn clients(&self) -> MutexGuard<'_, Vec<mpsc::Sender<Datagram>>> {
        self.clients.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn subscribe(&self) -> mpsc::Receiver<Datagram> {
        let (tx, rx) = mpsc::channel();
        self.clients().push(tx);
        rx
    }

    /// Hands every datagram from the interface to every client, until no client holds the listener.
    fn receive(listener: &Weak<Self>) {
        let mut buf = [0u8; 65536];
        while let Some(listener) = listener.upgrade() {
            listener.follow_interface();
            let (socket, index) = listener.current();
            match socket.recv_from(&mut buf) {
                Ok((len, src)) if arrived_on(src, index) => listener
                    .clients()
                    // Dropped clients are forgotten here.
                    .retain(|tx| tx.send(buf[..len].to_vec()).is_ok()),
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
    replies: &mpsc::Receiver<Datagram>,
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
