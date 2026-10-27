//! DNS servers from stateless DHCPv6 (`dhcpv6` feature): Information-Request, RFC 8415 section 18.2.6.

use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, Weak};
use std::time::{Duration, Instant};

use fqdn::FQDN;
use socket2::{Domain, Protocol, SockRef, Socket, Type};

use crate::ClientId;
use crate::custom::{if_index, lookup_on_interface};
use crate::duid::random_u32;

/// How long a lookup waits for the first Reply.
const FIRST_REPLY_TIMEOUT: Duration = Duration::from_secs(3);
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

/// Equal when using the same interface.
impl PartialEq for Dhcpv6ResolverConfig {
    fn eq(&self, other: &Self) -> bool {
        self.interface == other.interface
    }
}

impl Eq for Dhcpv6ResolverConfig {}

impl std::hash::Hash for Dhcpv6ResolverConfig {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.interface.hash(state);
    }
}

impl Dhcpv6ResolverConfig {
    /// Starts sending DHCPv6 Information-Requests on `interface` right away, and again
    /// whenever the server's information refresh time passes.
    ///
    /// `client_id` is required on purpose, because some networks only answer a particular one
    /// (e.g. NTT's NGN needs [`ClientId::DuidLl`] with the interface's MAC address); see [`ClientId`].
    ///
    /// This binds UDP port 546, which needs privileges on most platforms (e.g.
    /// `CAP_NET_BIND_SERVICE` on Linux).
    ///
    /// Another DHCPv6 client on the host that is bound to the interface's address (e.g.
    /// systemd-networkd) receives the Replies instead, so this then gets no DNS servers.
    ///
    /// The interface does not need to exist yet.
    pub fn new(interface: impl Into<String>, client_id: ClientId) -> io::Result<Self> {
        let interface = interface.into();
        client_id.validate()?;
        let client_id = client_id.resolve();
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_only_v6(true)?;
        // Wildcard address: never takes Replies away from a client bound to the link-local address.
        socket.set_reuse_address(true)?;
        socket.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, CLIENT_PORT)).into())?;
        let socket = UdpSocket::from(socket);

        let shared = Arc::new(Shared::default());
        let weak = Arc::downgrade(&shared);
        let thread_interface = interface.clone();
        std::thread::Builder::new()
            .name("iphost-dhcpv6".into())
            .spawn({
                let duid = client_id.duid();
                move || run(&socket, &thread_interface, duid.as_deref(), &weak)
            })?;
        Ok(Self {
            interface,
            client_id,
            shared,
        })
    }

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

    pub(crate) fn lookup(&self, fqdn: &FQDN) -> io::Result<Vec<IpAddr>> {
        let servers = {
            let servers = self.shared.servers();
            let (servers, _) = self
                .shared
                .cond
                .wait_timeout_while(servers, FIRST_REPLY_TIMEOUT, |s| s.is_none())
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

impl Shared {
    fn servers(&self) -> MutexGuard<'_, Option<Vec<Ipv6Addr>>> {
        self.servers.lock().unwrap_or_else(PoisonError::into_inner)
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

fn run(socket: &UdpSocket, interface: &str, duid: Option<&[u8]>, shared: &Weak<Shared>) {
    let mut buf = [0u8; 65536];
    let mut exchange: Option<Exchange> = None;
    let mut next_send = Instant::now();

    while let Some(shared) = shared.upgrade() {
        let now = Instant::now();
        if now >= next_send {
            let ex = exchange.get_or_insert_with(|| Exchange {
                xid: random_u32().to_be_bytes()[1..].try_into().unwrap(),
                started: now,
                rt: jitter(INF_TIMEOUT),
            });
            if let Err(_e) = send(socket, interface, duid, ex, now) {
                #[cfg(feature = "tracing")]
                tracing::debug!(error = %_e, interface, "DHCPv6 Information-Request failed");
            }
            next_send = now + ex.rt;
            ex.rt = jitter((ex.rt * 2).min(INF_MAX_RT));
        }

        let timeout = next_send
            .saturating_duration_since(Instant::now())
            .clamp(Duration::from_millis(10), RECV_TIMEOUT);
        let _ = socket.set_read_timeout(Some(timeout));
        let (len, src) = match socket.recv_from(&mut buf) {
            Ok(received) => received,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(_e) => {
                #[cfg(feature = "tracing")]
                tracing::warn!(error = %_e, interface, "DHCPv6 receive failed");
                std::thread::sleep(RECV_TIMEOUT);
                continue;
            }
        };

        let Some(ex) = &exchange else { continue };
        // A link-local source carries the arrival interface as its scope.
        if let SocketAddr::V6(src) = src
            && src.ip().is_unicast_link_local()
            && if_index(interface).ok() != Some(src.scope_id())
        {
            continue;
        }
        let Some(reply) = parse_reply(&buf[..len], ex.xid, duid) else {
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
    fn jitter_bounds() {
        for _ in 0..100 {
            let d = jitter(Duration::from_secs(10));
            assert!(d >= Duration::from_secs(9) && d <= Duration::from_secs(11));
        }
    }
}
