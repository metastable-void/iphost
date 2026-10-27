//! DNS servers from IPv6 Router Advertisements (`ra` feature): RDNSS, RFC 8106.
// Only the "unsupported" stub uses this module outside of Unix.
#![cfg_attr(not(unix), allow(dead_code))]

use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use fqdn::FQDN;

use crate::{BindDevice, StaticResolverConfig};

/// How long a lookup waits for the first RA with DNS servers.
const FIRST_RA_TIMEOUT: Duration = Duration::from_secs(3);

/// Netlink delivers one message per RDNSS option; messages from the same router this close
/// together are treated as one RA.
const MERGE_WINDOW: Duration = Duration::from_secs(1);

const ND_ROUTER_SOLICIT: u8 = 133;
const ND_ROUTER_ADVERT: u8 = 134;
const ND_OPT_RDNSS: u8 = 25;

/// Configuration for [`Resolver::Ra`](crate::Resolver::Ra): DNS servers advertised by routers on an interface.
///
/// Clones share one listener, which stops when the last clone is dropped.
#[cfg_attr(docsrs, doc(cfg(feature = "ra")))]
#[derive(Clone)]
pub struct RaResolverConfig {
    interface: String,
    shared: Arc<Shared>,
}

impl std::fmt::Debug for RaResolverConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RaResolverConfig")
            .field("interface", &self.interface)
            .field("nameservers", &self.nameservers())
            .finish()
    }
}

/// Equal when listening on the same interface.
impl PartialEq for RaResolverConfig {
    fn eq(&self, other: &Self) -> bool {
        self.interface == other.interface
    }
}

impl Eq for RaResolverConfig {}

impl std::hash::Hash for RaResolverConfig {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.interface.hash(state);
    }
}

impl RaResolverConfig {
    /// Starts listening for Router Advertisements on `interface` right away.
    ///
    /// With the privileges for a raw ICMPv6 socket (e.g. `CAP_NET_RAW` on Linux), RAs are read
    /// directly, even when the kernel does not process them (`accept_ra=0`), and Router
    /// Solicitations are sent to speed things up.
    ///
    /// Without them, on Linux, the kernel's RA options are read from netlink instead. This only
    /// works when the kernel processes RAs on the interface, and waits for the next unsolicited RA.
    /// Elsewhere, this fails without privileges.
    ///
    /// The interface does not need to exist yet.
    pub fn new(interface: impl Into<String>) -> io::Result<Self> {
        let interface = interface.into();
        let shared = Arc::new(Shared::default());
        sys::spawn(interface.clone(), Arc::downgrade(&shared))?;
        Ok(Self { interface, shared })
    }

    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Current DNS servers: the unexpired ones, or the expired ones if none are left.
    pub fn nameservers(&self) -> Vec<Ipv6Addr> {
        self.shared.state().current(Instant::now())
    }

    pub(crate) fn lookup(&self, fqdn: &FQDN) -> io::Result<Vec<IpAddr>> {
        let servers = {
            let state = self.shared.state();
            let (state, _) = self
                .shared
                .cond
                .wait_timeout_while(state, FIRST_RA_TIMEOUT, |s| s.servers.is_empty())
                .unwrap_or_else(PoisonError::into_inner);
            state.current(Instant::now())
        };
        if servers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no DNS servers from router advertisements",
            ));
        }
        StaticResolverConfig::new(servers.into_iter().map(|a| SocketAddr::new(a.into(), 53)))
            .with_bind_device(BindDevice::Interface(self.interface.clone()))
            .lookup(fqdn)
    }
}

#[derive(Debug, Default)]
struct Shared {
    state: Mutex<State>,
    cond: Condvar,
}

impl Shared {
    // State is consistent after every update, so a poisoned lock is safe to reuse.
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn apply(&self, update: Update) {
        self.state().apply(update, Instant::now());
        self.cond.notify_all();
    }
}

/// RDNSS options from one RA (or one netlink message).
#[derive(Debug, PartialEq, Eq)]
struct Update {
    router: Ipv6Addr,
    /// Addresses with their lifetimes in seconds.
    servers: Vec<(Ipv6Addr, u32)>,
    /// False when this may be only part of an RA (netlink).
    complete: bool,
}

#[derive(Debug, Default)]
struct State {
    servers: Vec<Server>,
    last: Option<(Ipv6Addr, Instant)>,
}

#[derive(Debug)]
struct Server {
    addr: Ipv6Addr,
    /// `None` is infinite.
    expiry: Option<Instant>,
}

impl State {
    /// A new RA overwrites the previous servers. Lifetime 0 withdraws a server.
    fn apply(&mut self, update: Update, now: Instant) {
        let merge = !update.complete
            && self.last.is_some_and(|(router, at)| {
                router == update.router && now.duration_since(at) < MERGE_WINDOW
            });
        if !merge {
            self.servers.clear();
        }
        for (addr, lifetime) in update.servers {
            self.servers.retain(|s| s.addr != addr);
            if lifetime != 0 {
                self.servers.push(Server {
                    addr,
                    expiry: (lifetime != u32::MAX)
                        .then(|| now + Duration::from_secs(lifetime.into())),
                });
            }
        }
        self.last = Some((update.router, now));
    }

    /// Unexpired servers, or the stale ones while no new values are available.
    fn current(&self, now: Instant) -> Vec<Ipv6Addr> {
        let live: Vec<_> = self
            .servers
            .iter()
            .filter(|s| s.expiry.is_none_or(|e| e > now))
            .map(|s| s.addr)
            .collect();
        if live.is_empty() {
            self.servers.iter().map(|s| s.addr).collect()
        } else {
            live
        }
    }
}

/// RDNSS entries in ND options. `None` if there is no RDNSS option or the options are malformed.
fn parse_rdnss(mut opts: &[u8]) -> Option<Vec<(Ipv6Addr, u32)>> {
    let mut found = None;
    while !opts.is_empty() {
        let len = usize::from(*opts.get(1)?) * 8;
        if len == 0 || len > opts.len() {
            return None;
        }
        let (opt, rest) = opts.split_at(len);
        // RFC 8106: length is 3 or more and odd (header + 16 bytes per address).
        if opt[0] == ND_OPT_RDNSS && len >= 24 && (len / 8) % 2 == 1 {
            let lifetime = u32::from_be_bytes(opt[4..8].try_into().unwrap());
            let list: &mut Vec<_> = found.get_or_insert_default();
            for addr in opt[8..].as_chunks::<16>().0 {
                list.push((Ipv6Addr::from(*addr), lifetime));
            }
        }
        opts = rest;
    }
    found
}

/// Validates an RA (RFC 4861 section 6.1.2). The checksum is verified by the kernel.
fn parse_ra(packet: &[u8], src: Ipv6Addr, hop_limit: Option<i32>) -> Option<Update> {
    if packet.len() < 16
        || packet[0] != ND_ROUTER_ADVERT
        || packet[1] != 0
        || hop_limit != Some(255)
        || !src.is_unicast_link_local()
    {
        return None;
    }
    Some(Update {
        router: src,
        servers: parse_rdnss(&packet[16..])?,
        complete: true,
    })
}

#[cfg(unix)]
mod sys {
    use std::io;
    use std::mem::{size_of, zeroed};
    use std::net::{Ipv6Addr, SocketAddrV6};
    use std::os::fd::{AsRawFd, RawFd};
    use std::sync::Weak;
    use std::time::{Duration, Instant};

    use socket2::{Domain, Protocol, SockAddr, Socket, Type};

    use super::{ND_ROUTER_ADVERT, ND_ROUTER_SOLICIT, Shared, Update, parse_ra};
    use crate::custom::{if_index, setsockopt_int};

    /// Also how often the thread notices that every config was dropped.
    const RECV_TIMEOUT: Duration = Duration::from_secs(1);
    /// RFC 4861 MAX_RTR_SOLICITATIONS / RTR_SOLICITATION_INTERVAL.
    const MAX_RTR_SOLICITATIONS: u32 = 3;
    const RTR_SOLICITATION_INTERVAL: Duration = Duration::from_secs(4);

    #[cfg(any(target_os = "openbsd", target_os = "netbsd"))]
    const IPV6_RECVHOPLIMIT: libc::c_int = 37; // KAME, as on FreeBSD and macOS; missing from libc.
    #[cfg(any(target_os = "illumos", target_os = "solaris"))]
    const IPV6_RECVHOPLIMIT: libc::c_int = 0x13; // missing from libc.
    #[cfg(not(any(
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "illumos",
        target_os = "solaris"
    )))]
    const IPV6_RECVHOPLIMIT: libc::c_int = libc::IPV6_RECVHOPLIMIT;

    #[cfg(any(target_os = "openbsd", target_os = "netbsd"))]
    const IPV6_HOPLIMIT: libc::c_int = 47; // KAME, as on FreeBSD and macOS; missing from libc.
    #[cfg(not(any(target_os = "openbsd", target_os = "netbsd")))]
    const IPV6_HOPLIMIT: libc::c_int = libc::IPV6_HOPLIMIT;

    enum Source {
        Raw(Socket),
        #[cfg(target_os = "linux")]
        Netlink(Socket),
    }

    pub(super) fn spawn(interface: String, shared: Weak<Shared>) -> io::Result<()> {
        let source = match open_raw() {
            Ok(socket) => Source::Raw(socket),
            #[cfg(target_os = "linux")]
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                Source::Netlink(netlink::open()?)
            }
            Err(e) => return Err(e),
        };
        std::thread::Builder::new()
            .name("iphost-ra".into())
            .spawn(move || run(source, &interface, &shared))?;
        Ok(())
    }

    fn open_raw() -> io::Result<Socket> {
        let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
        setsockopt_int(socket.as_raw_fd(), libc::IPPROTO_IPV6, IPV6_RECVHOPLIMIT, 1)?;
        socket.set_multicast_hops_v6(255)?;
        socket.set_read_timeout(Some(RECV_TIMEOUT))?;
        Ok(socket)
    }

    fn run(source: Source, interface: &str, shared: &Weak<Shared>) {
        let mut buf = vec![0u8; 65536];
        let mut solicitations = 0;
        let mut next_solicitation = Instant::now();

        while let Some(shared) = shared.upgrade() {
            let updates = match &source {
                Source::Raw(socket) => {
                    if solicitations < MAX_RTR_SOLICITATIONS
                        && shared.state().last.is_none()
                        && Instant::now() >= next_solicitation
                    {
                        solicitations += 1;
                        next_solicitation = Instant::now() + RTR_SOLICITATION_INTERVAL;
                        if let Err(_e) = solicit(socket, interface) {
                            #[cfg(feature = "tracing")]
                            tracing::debug!(error = %_e, interface, "Router Solicitation failed");
                        }
                    }
                    recv_ra(socket.as_raw_fd(), &mut buf, interface).map(Vec::from_iter)
                }
                #[cfg(target_os = "linux")]
                Source::Netlink(socket) => netlink::recv(socket, &mut buf, interface),
            };
            match updates {
                Ok(updates) => {
                    for update in updates {
                        #[cfg(feature = "tracing")]
                        tracing::debug!(?update, interface, "RA DNS servers");
                        shared.apply(update);
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Err(_e) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!(error = %_e, interface, "RA receive failed");
                    std::thread::sleep(RECV_TIMEOUT);
                }
            }
        }

        #[cfg(feature = "tracing")]
        tracing::debug!(interface, "RA listener stopped");
    }

    fn solicit(socket: &Socket, interface: &str) -> io::Result<()> {
        let index = if_index(interface)?;
        socket.set_multicast_if_v6(index)?;
        // ff02::2, all routers. The kernel fills in the checksum.
        let dst = SocketAddrV6::new(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2), 0, 0, index);
        socket.send_to(
            &[ND_ROUTER_SOLICIT, 0, 0, 0, 0, 0, 0, 0],
            &SockAddr::from(dst),
        )?;
        Ok(())
    }

    /// Receives one ICMPv6 packet, returning an update if it is a valid RA with RDNSS on `interface`.
    fn recv_ra(fd: RawFd, buf: &mut [u8], interface: &str) -> io::Result<Option<Update>> {
        // SAFETY: all-zero is valid for these C structs.
        let mut src: libc::sockaddr_in6 = unsafe { zeroed() };
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let mut control = [0u64; 32]; // u64 for cmsghdr alignment.
        let mut msg: libc::msghdr = unsafe { zeroed() };
        msg.msg_name = (&raw mut src).cast();
        msg.msg_namelen = size_of::<libc::sockaddr_in6>() as _;
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = size_of_val(&control) as _;

        // SAFETY: every pointer in `msg` is valid for the given lengths during the call.
        let len = unsafe { libc::recvmsg(fd, &mut msg, 0) };
        if len < 0 {
            return Err(io::Error::last_os_error());
        }
        let packet = &buf[..len as usize];
        if packet.first() != Some(&ND_ROUTER_ADVERT) {
            return Ok(None);
        }

        let mut hop_limit = None;
        // SAFETY: `msg` was filled in by recvmsg; CMSG_* walk only its control buffer.
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == libc::IPPROTO_IPV6 && (*cmsg).cmsg_type == IPV6_HOPLIMIT {
                    hop_limit = Some(libc::CMSG_DATA(cmsg).cast::<libc::c_int>().read_unaligned());
                }
                cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            }
        }

        // Link-local sources carry the arrival interface as their scope.
        if src.sin6_scope_id != if_index(interface)? {
            return Ok(None);
        }
        Ok(parse_ra(
            packet,
            Ipv6Addr::from(src.sin6_addr.s6_addr),
            hop_limit,
        ))
    }

    /// Unprivileged fallback: RA options the kernel forwards (`RTM_NEWNDUSEROPT`).
    #[cfg(target_os = "linux")]
    mod netlink {
        use std::io::{self, Read};
        use std::mem::{size_of, zeroed};
        use std::net::Ipv6Addr;
        use std::os::fd::AsRawFd;

        use socket2::{Domain, Protocol, Socket, Type};

        use super::super::{ND_ROUTER_ADVERT, Update, parse_rdnss};
        use super::RECV_TIMEOUT;
        use crate::custom::{if_index, setsockopt_int};

        const NETLINK_ADD_MEMBERSHIP: libc::c_int = 1;
        const NDUSEROPT_SRCADDR: u16 = 1;

        pub(super) fn open() -> io::Result<Socket> {
            let socket = Socket::new(
                Domain::from(libc::AF_NETLINK),
                Type::RAW,
                Some(Protocol::from(libc::NETLINK_ROUTE)),
            )?;
            // SAFETY: all-zero is a valid `sockaddr_nl` (autobind, no groups).
            let mut addr: libc::sockaddr_nl = unsafe { zeroed() };
            addr.nl_family = libc::AF_NETLINK as _;
            // SAFETY: `addr` is a valid `sockaddr_nl` of the given length.
            let ret = unsafe {
                libc::bind(
                    socket.as_raw_fd(),
                    (&raw const addr).cast(),
                    size_of::<libc::sockaddr_nl>() as _,
                )
            };
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
            setsockopt_int(
                socket.as_raw_fd(),
                libc::SOL_NETLINK,
                NETLINK_ADD_MEMBERSHIP,
                libc::RTNLGRP_ND_USEROPT as _,
            )?;
            socket.set_read_timeout(Some(RECV_TIMEOUT))?;
            Ok(socket)
        }

        pub(super) fn recv(
            mut socket: &Socket,
            buf: &mut [u8],
            interface: &str,
        ) -> io::Result<Vec<Update>> {
            let len = socket.read(buf)?;
            Ok(parse(&buf[..len], if_index(interface)?))
        }

        fn u16_at(b: &[u8], at: usize) -> Option<u16> {
            Some(u16::from_ne_bytes(b.get(at..at + 2)?.try_into().unwrap()))
        }

        fn u32_at(b: &[u8], at: usize) -> Option<u32> {
            Some(u32::from_ne_bytes(b.get(at..at + 4)?.try_into().unwrap()))
        }

        fn align4(n: usize) -> usize {
            (n + 3) & !3
        }

        /// Parses netlink messages, keeping RDNSS from RAs on `ifindex`.
        pub(in crate::ra) fn parse(mut buf: &[u8], ifindex: u32) -> Vec<Update> {
            let mut updates = Vec::new();
            while let Some(len) = u32_at(buf, 0).map(|l| l as usize) {
                if len < 16 || len > buf.len() {
                    break;
                }
                if u16_at(buf, 4) == Some(libc::RTM_NEWNDUSEROPT) {
                    updates.extend(parse_useropt(&buf[16..len], ifindex));
                }
                buf = &buf[align4(len).min(buf.len())..];
            }
            updates
        }

        /// `struct nduseroptmsg`, the ND options, then `NDUSEROPT_SRCADDR`.
        fn parse_useropt(msg: &[u8], ifindex: u32) -> Option<Update> {
            let opts_len = usize::from(u16_at(msg, 2)?);
            if *msg.first()? != libc::AF_INET6 as u8
                || u32_at(msg, 4)? != ifindex
                || *msg.get(8)? != ND_ROUTER_ADVERT
            {
                return None;
            }
            let servers = parse_rdnss(msg.get(16..16 + opts_len)?)?;

            let mut attrs = msg.get(align4(16 + opts_len)..)?;
            let mut router = None;
            while let (Some(len), Some(ty)) = (u16_at(attrs, 0), u16_at(attrs, 2)) {
                let len = usize::from(len);
                if len < 4 || len > attrs.len() {
                    break;
                }
                if ty == NDUSEROPT_SRCADDR && len == 20 {
                    router = Some(Ipv6Addr::from(<[u8; 16]>::try_from(&attrs[4..20]).unwrap()));
                }
                attrs = &attrs[align4(len).min(attrs.len())..];
            }

            Some(Update {
                router: router?,
                servers,
                complete: false,
            })
        }
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(super) use netlink::parse as parse_netlink;
}

#[cfg(not(unix))]
mod sys {
    use std::io;
    use std::sync::Weak;

    pub(super) fn spawn(_interface: String, _shared: Weak<super::Shared>) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "router advertisements are not supported on this platform",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTER: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    const DNS1: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x53);
    const DNS2: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x54);

    fn rdnss_opt(lifetime: u32, addrs: &[Ipv6Addr]) -> Vec<u8> {
        let mut opt = vec![ND_OPT_RDNSS, (1 + 2 * addrs.len()) as u8, 0, 0];
        opt.extend(lifetime.to_be_bytes());
        for a in addrs {
            opt.extend(a.octets());
        }
        opt
    }

    fn ra(opts: &[u8]) -> Vec<u8> {
        let mut packet = vec![
            ND_ROUTER_ADVERT,
            0,
            0,
            0,
            64,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        packet.extend(opts);
        packet
    }

    fn update(servers: &[(Ipv6Addr, u32)], complete: bool) -> Update {
        Update {
            router: ROUTER,
            servers: servers.to_vec(),
            complete,
        }
    }

    #[test]
    fn parses_rdnss() {
        // A source link-layer address option before RDNSS.
        let mut opts = vec![1, 1, 0, 0, 0, 0, 0, 0];
        opts.extend(rdnss_opt(600, &[DNS1, DNS2]));
        assert_eq!(parse_rdnss(&opts), Some(vec![(DNS1, 600), (DNS2, 600)]));
        assert_eq!(parse_rdnss(&[1, 1, 0, 0, 0, 0, 0, 0]), None);
        assert_eq!(parse_rdnss(&[ND_OPT_RDNSS, 0, 0, 0]), None);
        assert_eq!(parse_rdnss(&[ND_OPT_RDNSS, 3, 0, 0]), None);
    }

    #[test]
    fn validates_ra() {
        let packet = ra(&rdnss_opt(600, &[DNS1]));
        assert_eq!(
            parse_ra(&packet, ROUTER, Some(255)),
            Some(update(&[(DNS1, 600)], true))
        );
        assert_eq!(parse_ra(&packet, ROUTER, Some(64)), None);
        assert_eq!(parse_ra(&packet, ROUTER, None), None);
        assert_eq!(parse_ra(&packet, DNS1, Some(255)), None);
        assert_eq!(parse_ra(&ra(&[]), ROUTER, Some(255)), None);
    }

    #[test]
    fn new_ra_overwrites() {
        let now = Instant::now();
        let mut state = State::default();
        state.apply(update(&[(DNS1, 600)], true), now);
        state.apply(update(&[(DNS2, 600)], true), now);
        assert_eq!(state.current(now), vec![DNS2]);
    }

    #[test]
    fn netlink_parts_merge_within_window() {
        let now = Instant::now();
        let mut state = State::default();
        state.apply(update(&[(DNS1, 600)], false), now);
        state.apply(update(&[(DNS2, 600)], false), now);
        assert_eq!(state.current(now), vec![DNS1, DNS2]);
        state.apply(update(&[(DNS2, 600)], false), now + MERGE_WINDOW);
        assert_eq!(state.current(now), vec![DNS2]);
    }

    #[test]
    fn lifetimes() {
        let now = Instant::now();
        let later = now + Duration::from_secs(120);
        let mut state = State::default();
        state.apply(update(&[(DNS1, 60), (DNS2, u32::MAX)], true), now);
        assert_eq!(state.current(later), vec![DNS2]);

        // Expired servers are still used while nothing newer is known.
        state.apply(update(&[(DNS1, 60)], true), now);
        assert_eq!(state.current(later), vec![DNS1]);

        // Lifetime 0 withdraws.
        state.apply(update(&[(DNS1, 0)], true), now);
        assert!(state.current(now).is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_netlink_useropt() {
        let opt = rdnss_opt(600, &[DNS1]);
        let mut msg = vec![libc::AF_INET6 as u8, 0];
        msg.extend((opt.len() as u16).to_ne_bytes());
        msg.extend(7i32.to_ne_bytes());
        msg.extend([ND_ROUTER_ADVERT, 0, 0, 0, 0, 0, 0, 0]);
        msg.extend(&opt);
        msg.extend(20u16.to_ne_bytes());
        msg.extend(1u16.to_ne_bytes());
        msg.extend(ROUTER.octets());

        let mut buf = Vec::new();
        buf.extend((16 + msg.len() as u32).to_ne_bytes());
        buf.extend(libc::RTM_NEWNDUSEROPT.to_ne_bytes());
        buf.extend([0u8; 10]);
        buf.extend(&msg);

        assert_eq!(
            sys::parse_netlink(&buf, 7),
            vec![update(&[(DNS1, 600)], false)]
        );
        assert!(sys::parse_netlink(&buf, 8).is_empty());
    }
}
