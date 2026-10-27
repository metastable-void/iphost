//! Custom DNS resolvers (`custom` feature): a minimal stub client (RFC 1035) on std sockets.

use std::hash::{BuildHasher, RandomState};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use fqdn::FQDN;
use socket2::{Domain, Protocol, SockRef, Socket, Type};

/// Per nameserver and attempt: the UDP exchange plus any TCP retry after truncation.
pub(crate) const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
/// Passes over the nameserver list.
pub(crate) const ATTEMPTS: u32 = 2;
/// Discovered nameservers (RA, DHCPv6) used per lookup; `MAXNS` of resolv.conf.
#[cfg(any(feature = "ra", feature = "dhcpv6"))]
pub(crate) const MAX_SERVERS: usize = 3;
/// How long a discovering resolver waits for its first nameservers.
#[cfg(any(feature = "ra", feature = "dhcpv6"))]
pub(crate) const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(3);

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
const RCODE_NXDOMAIN: u8 = 3;
const FLAG_TC: u8 = 0x02;

/// Upper bound on a [`StaticResolverConfig`] lookup over `servers` nameservers.
pub(crate) fn query_time_bound(servers: usize) -> Duration {
    let tries = u32::try_from(servers)
        .unwrap_or(u32::MAX)
        .saturating_mul(ATTEMPTS);
    QUERY_TIMEOUT.saturating_mul(tries)
}

/// Keyed SipHash of the clock with per-thread random keys: unpredictable without the keys.
pub(crate) fn random_u32() -> u32 {
    RandomState::new().hash_one(Instant::now()) as u32
}

/// Device to bind resolver sockets to.
#[cfg_attr(docsrs, doc(cfg(feature = "custom")))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BindDevice {
    /// Network interface name.
    ///
    /// - Linux: `SO_BINDTODEVICE`.
    /// - Apple platforms, illumos, Solaris: `IP_BOUND_IF` / `IPV6_BOUND_IF` by interface index.
    /// - OpenBSD / FreeBSD: no per-socket interface binding exists, so sockets use the
    ///   interface's routing domain (`SO_RTABLE`) / FIB (`SO_SETFIB`) instead.
    /// - Elsewhere (e.g. NetBSD): sockets are not bound.
    ///
    /// Everywhere, the interface is also the scope of link-local nameservers without one.
    /// The interface is looked up on every query, so a recreated interface is picked up.
    Interface(String),

    /// VRF.
    ///
    /// - Linux: VRF device name (`SO_BINDTODEVICE`).
    /// - OpenBSD: routing domain number (`SO_RTABLE`).
    /// - FreeBSD: FIB number (`SO_SETFIB`).
    #[cfg(any(target_os = "linux", target_os = "openbsd", target_os = "freebsd"))]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(target_os = "linux", target_os = "openbsd", target_os = "freebsd")))
    )]
    Vrf(String),
}

/// Configuration for [`Resolver::Static`](crate::Resolver::Static).
#[cfg_attr(docsrs, doc(cfg(feature = "custom")))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StaticResolverConfig {
    nameservers: Vec<SocketAddr>,
    bind_device: Option<BindDevice>,
}

impl StaticResolverConfig {
    /// Nameservers to query over UDP (falling back to TCP on truncation), usually on port 53.
    ///
    /// A lookup asks them in order until one answers, trying the list twice, with a fixed
    /// timeout per query; see [`Resolver::max_lookup_time`](crate::Resolver::max_lookup_time).
    ///
    /// A link-local IPv6 nameserver needs either a scope ID in its address,
    /// or a [`BindDevice::Interface`].
    pub fn new(nameservers: impl IntoIterator<Item = SocketAddr>) -> Self {
        Self {
            nameservers: nameservers.into_iter().collect(),
            bind_device: None,
        }
    }

    /// Binds resolver sockets to a device, builder-style.
    pub fn with_bind_device(mut self, bind_device: BindDevice) -> Self {
        self.bind_device = Some(bind_device);
        self
    }

    pub fn nameservers(&self) -> &[SocketAddr] {
        &self.nameservers
    }

    pub fn bind_device(&self) -> Option<&BindDevice> {
        self.bind_device.as_ref()
    }

    /// Blocking lookup: A and AAAA records, queried in parallel.
    pub(crate) fn lookup(&self, fqdn: &FQDN) -> io::Result<Vec<IpAddr>> {
        if self.nameservers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no nameservers configured",
            ));
        }
        // Already in wire format: length-prefixed labels ending in the root label.
        let name = fqdn.as_bytes();
        let (v6, v4) = std::thread::scope(|scope| {
            let v4 = std::thread::Builder::new()
                .name("iphost-dns".into())
                .spawn_scoped(scope, || self.query(name, TYPE_A));
            let v6 = self.query(name, TYPE_AAAA);
            let v4 = v4.and_then(|thread| {
                thread
                    .join()
                    .unwrap_or_else(|_| Err(io::Error::other("A query panicked")))
            });
            (v6, v4)
        });
        let addrs: Vec<IpAddr> = match (v6, v4) {
            (Err(e), Err(_)) => return Err(e),
            (v6, v4) => v6
                .into_iter()
                .flatten()
                .chain(v4.into_iter().flatten())
                .collect(),
        };
        if addrs.is_empty() {
            // As with `getaddrinfo`, a name without address records is an error.
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no address records",
            ));
        }
        Ok(addrs)
    }

    /// `qtype` records from the first nameserver that answers, trying the list [`ATTEMPTS`] times.
    fn query(&self, name: &[u8], qtype: u16) -> io::Result<Vec<IpAddr>> {
        let mut last = io::Error::new(io::ErrorKind::TimedOut, "no nameserver answered");
        for _ in 0..ATTEMPTS {
            for &server in &self.nameservers {
                match self.query_server(server, name, qtype) {
                    Ok(addrs) => return Ok(addrs),
                    Err(Failure::NoSuchName) => {
                        return Err(io::Error::new(io::ErrorKind::NotFound, "no such name"));
                    }
                    Err(Failure::Other(e)) => {
                        #[cfg(feature = "tracing")]
                        tracing::debug!(%server, error = %e, "DNS query failed");
                        last = e;
                    }
                }
            }
        }
        Err(last)
    }

    /// One query to `server` within [`QUERY_TIMEOUT`]: UDP, then TCP if the answer was truncated.
    fn query_server(
        &self,
        server: SocketAddr,
        name: &[u8],
        qtype: u16,
    ) -> Result<Vec<IpAddr>, Failure> {
        let deadline = Instant::now() + QUERY_TIMEOUT;
        let target = with_scope(server, self.scope_id(server)?);
        let id = random_u32() as u16;
        let query = build_query(id, name, qtype);

        let socket = self.socket(target, Type::DGRAM, Protocol::UDP)?;
        socket.connect(&target.into())?;
        let socket = UdpSocket::from(socket);
        socket.send(&query)?;
        let mut buf = vec![0u8; usize::from(u16::MAX)];
        let len = loop {
            socket.set_read_timeout(Some(remaining(deadline)?))?;
            let len = match socket.recv(&mut buf) {
                // A signal; timed socket calls are not restarted.
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                len => len?,
            };
            // Only the server reaches a connected socket, so this is a stale or spoofed datagram.
            if question_end(&buf[..len], id, name, qtype).is_some() {
                break len;
            }
        };
        let response = &buf[..len];
        if response[2] & FLAG_TC != 0 {
            let full = self.exchange_tcp(target, &query, deadline)?;
            return parse_response(&full, id, name, qtype);
        }
        parse_response(response, id, name, qtype)
    }

    /// The query over TCP (RFC 1035 section 4.2.2), for answers too large for UDP.
    fn exchange_tcp(
        &self,
        target: SocketAddr,
        query: &[u8],
        deadline: Instant,
    ) -> io::Result<Vec<u8>> {
        let socket = self.socket(target, Type::STREAM, Protocol::TCP)?;
        socket.connect_timeout(&target.into(), remaining(deadline)?)?;
        let mut stream = TcpStream::from(socket);
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        let len = u16::try_from(query.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "query too long"))?;
        stream.write_all(&[&len.to_be_bytes()[..], query].concat())?;
        let mut len = [0u8; 2];
        read_full(&mut stream, &mut len, deadline)?;
        let mut response = vec![0u8; usize::from(u16::from_be_bytes(len))];
        read_full(&mut stream, &mut response, deadline)?;
        Ok(response)
    }

    /// A socket towards `target`, bound as [`BindDevice`] says.
    fn socket(&self, target: SocketAddr, ty: Type, protocol: Protocol) -> io::Result<Socket> {
        let socket = Socket::new(Domain::for_address(target), ty, Some(protocol))?;
        let sock = SockRef::from(&socket);
        match &self.bind_device {
            None => {}
            Some(BindDevice::Interface(name)) => bind_to_interface(&sock, name, target.is_ipv6())?,
            #[cfg(target_os = "linux")]
            Some(BindDevice::Vrf(name)) => sock.bind_device(Some(name.as_bytes()))?,
            #[cfg(any(target_os = "openbsd", target_os = "freebsd"))]
            Some(BindDevice::Vrf(table)) => rtable::set(
                &sock,
                table.parse().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "VRF must be a routing table number",
                    )
                })?,
            )?,
        }
        Ok(socket)
    }

    /// Scope ID for a link-local nameserver without one: the bound interface's index.
    fn scope_id(&self, server: SocketAddr) -> io::Result<u32> {
        match (server, &self.bind_device) {
            (SocketAddr::V6(addr), Some(BindDevice::Interface(name)))
                if addr.scope_id() == 0 && addr.ip().is_unicast_link_local() =>
            {
                if_index(name)
            }
            _ => Ok(0),
        }
    }
}

/// Why a nameserver gave no usable answer.
#[derive(Debug)]
enum Failure {
    /// NXDOMAIN: definite, so no other nameserver is asked.
    NoSuchName,
    Other(io::Error),
}

impl From<io::Error> for Failure {
    fn from(e: io::Error) -> Self {
        Failure::Other(e)
    }
}

/// Time left until `deadline`, or a timeout error.
fn remaining(deadline: Instant) -> io::Result<Duration> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "DNS query timed out",
        ));
    }
    Ok(left)
}

/// `read_exact` that keeps to `deadline` even when bytes trickle in.
fn read_full(stream: &mut TcpStream, buf: &mut [u8], deadline: Instant) -> io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        match stream.read(&mut buf[filled..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "nameserver closed the connection",
                ));
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// A recursive query for `qtype` records of `name` (wire format).
fn build_query(id: u16, name: &[u8], qtype: u16) -> Vec<u8> {
    let mut msg = id.to_be_bytes().to_vec();
    msg.extend([0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]); // RD; one question
    msg.extend_from_slice(name);
    msg.extend(qtype.to_be_bytes());
    msg.extend(CLASS_IN.to_be_bytes());
    msg
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(at..at + 2)?.try_into().unwrap()))
}

/// Offset past the question of a response to our query (RFC 5452 section 9.1 matching).
///
/// The question is the first name in the message, so it cannot be compressed.
fn question_end(msg: &[u8], id: u16, name: &[u8], qtype: u16) -> Option<usize> {
    let end = 12 + name.len() + 4;
    let question = msg.get(12..end)?;
    (u16_at(msg, 0)? == id
        && msg[2] & 0x80 != 0 // QR: a response
        && (msg[2] >> 3) & 0xF == 0 // to a standard query
        && u16_at(msg, 4)? == 1 // QDCOUNT
        && question[..name.len()].eq_ignore_ascii_case(name)
        && u16_at(question, name.len()) == Some(qtype)
        && u16_at(question, name.len() + 2) == Some(CLASS_IN))
    .then_some(end)
}

/// Offset past the name at `pos`, which may end in a compression pointer (RFC 1035 section 4.1.4).
fn skip_name(msg: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        match *msg.get(pos)? {
            0 => return Some(pos + 1),
            len @ 1..=63 => pos += 1 + usize::from(len),
            0xC0..=0xFF => return msg.get(pos + 1).map(|_| pos + 2),
            _ => return None, // reserved label types
        }
    }
}

/// Addresses of type `qtype` in the answer section of a response to our query.
///
/// Owner names are not checked, as in musl: a recursive resolver's answer section holds the
/// CNAME (or DNAME) chain from the query name and the addresses at its end, in any order, and
/// records of other types or classes are skipped. Nothing in a name is ever followed, so
/// pointer loops cannot occur. Authority and additional sections are ignored.
fn parse_response(msg: &[u8], id: u16, name: &[u8], qtype: u16) -> Result<Vec<IpAddr>, Failure> {
    let bad = |what: &str| {
        Failure::Other(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("malformed DNS response: {what}"),
        ))
    };
    let mut pos =
        question_end(msg, id, name, qtype).ok_or_else(|| bad("not an answer to the query"))?;
    match msg[3] & 0x0F {
        0 => {}
        RCODE_NXDOMAIN => return Err(Failure::NoSuchName),
        rcode => {
            return Err(Failure::Other(io::Error::other(format!(
                "nameserver failed the query, rcode {rcode}"
            ))));
        }
    }
    let mut addrs = Vec::new();
    for _ in 0..u16_at(msg, 6).unwrap_or(0) {
        pos = skip_name(msg, pos).ok_or_else(|| bad("record name"))?;
        let rtype = u16_at(msg, pos);
        let class = u16_at(msg, pos + 2);
        let rdlen = usize::from(u16_at(msg, pos + 8).ok_or_else(|| bad("record header"))?);
        let rdata = msg
            .get(pos + 10..pos + 10 + rdlen)
            .ok_or_else(|| bad("record data"))?;
        pos += 10 + rdlen;
        if rtype != Some(qtype) || class != Some(CLASS_IN) {
            continue; // e.g. the CNAME chain leading to the addresses
        }
        match qtype {
            TYPE_A if rdata.len() == 4 => {
                addrs.push(Ipv4Addr::from(<[u8; 4]>::try_from(rdata).unwrap()).into());
            }
            TYPE_AAAA if rdata.len() == 16 => {
                addrs.push(Ipv6Addr::from(<[u8; 16]>::try_from(rdata).unwrap()).into());
            }
            _ => return Err(bad("address length")),
        }
    }
    Ok(addrs)
}

/// Looks up `fqdn` via discovered `servers` (port 53), bound to `interface`, which also scopes
/// link-local servers. `source` names where the servers came from, for the error message.
#[cfg(any(feature = "ra", feature = "dhcpv6"))]
pub(crate) fn lookup_on_interface(
    mut servers: Vec<Ipv6Addr>,
    interface: &str,
    fqdn: &FQDN,
    source: &str,
) -> io::Result<Vec<IpAddr>> {
    if servers.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no DNS servers from {source}"),
        ));
    }
    // Keeps the lookup time bounded (see `Resolver::max_lookup_time`).
    servers.truncate(MAX_SERVERS);
    StaticResolverConfig::new(servers.into_iter().map(|a| SocketAddr::new(a.into(), 53)))
        .with_bind_device(BindDevice::Interface(interface.into()))
        .lookup(fqdn)
}

/// `setsockopt(2)` for options socket2 lacks.
#[cfg(all(
    unix,
    any(feature = "ra", target_os = "openbsd", target_os = "freebsd")
))]
pub(crate) fn setsockopt<T>(
    fd: std::os::fd::RawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: &T,
) -> io::Result<()> {
    // SAFETY: `value` outlives the call with the given length.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            std::ptr::from_ref(value).cast(),
            size_of::<T>() as libc::socklen_t,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(unix)]
pub(crate) fn if_index(name: &str) -> io::Result<u32> {
    let name = std::ffi::CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in interface name"))?;
    // SAFETY: `name` is a valid NUL-terminated string.
    match unsafe { libc::if_nametoindex(name.as_ptr()) } {
        0 => Err(io::Error::last_os_error()),
        index => Ok(index),
    }
}

#[cfg(windows)]
pub(crate) fn if_index(name: &str) -> io::Result<u32> {
    let name = std::ffi::CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in interface name"))?;
    // SAFETY: `name` is a valid NUL-terminated string.
    match unsafe {
        windows_sys::Win32::NetworkManagement::IpHelper::if_nametoindex(name.as_ptr().cast())
    } {
        0 => Err(io::Error::new(io::ErrorKind::NotFound, "no such interface")),
        index => Ok(index),
    }
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn if_index(_name: &str) -> io::Result<u32> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "interface binding is not supported on this platform",
    ))
}

/// Sets `scope_id` on link-local IPv6 targets that lack one.
fn with_scope(target: SocketAddr, scope_id: u32) -> SocketAddr {
    match target {
        SocketAddr::V6(mut addr)
            if scope_id != 0 && addr.scope_id() == 0 && addr.ip().is_unicast_link_local() =>
        {
            addr.set_scope_id(scope_id);
            addr.into()
        }
        addr => addr,
    }
}

/// Ties `socket` to `interface` for sending and receiving, as [`BindDevice::Interface`] documents.
///
/// On Linux, sockets not bound to a device do not receive packets from interfaces enslaved to
/// a VRF unless the `udp_l3mdev_accept` / `raw_l3mdev_accept` sysctls say so; this does not
/// depend on them.
pub(crate) fn bind_to_interface(
    socket: &SockRef<'_>,
    interface: &str,
    ipv6: bool,
) -> io::Result<()> {
    let _ = (socket, interface, ipv6);
    #[cfg(target_os = "linux")]
    {
        socket.bind_device(Some(interface.as_bytes()))
    }
    #[cfg(any(target_vendor = "apple", target_os = "illumos", target_os = "solaris"))]
    {
        let index = std::num::NonZeroU32::new(if_index(interface)?);
        if ipv6 {
            socket.bind_device_by_index_v6(index)
        } else {
            socket.bind_device_by_index_v4(index)
        }
    }
    #[cfg(any(target_os = "openbsd", target_os = "freebsd"))]
    {
        rtable::set(socket, rtable::of_interface(socket, interface)?)
    }
    #[cfg(not(any(
        target_os = "linux",
        target_vendor = "apple",
        target_os = "illumos",
        target_os = "solaris",
        target_os = "openbsd",
        target_os = "freebsd"
    )))]
    {
        Ok(())
    }
}

/// OpenBSD routing domains / FreeBSD FIBs.
#[cfg(any(target_os = "openbsd", target_os = "freebsd"))]
mod rtable {
    use std::io;
    use std::os::fd::AsRawFd;

    use libc::{c_int, c_ulong};
    use socket2::SockRef;

    #[cfg(target_os = "openbsd")]
    const SO_RTABLE: c_int = libc::SO_RTABLE;
    #[cfg(target_os = "freebsd")]
    const SO_RTABLE: c_int = libc::SO_SETFIB;

    /// `_IOWR('i', num, struct ifreq)`; these ioctls are missing from libc.
    const fn iowr(num: c_ulong) -> c_ulong {
        0xc000_0000
            | ((size_of::<libc::ifreq>() as c_ulong & 0x1fff) << 16)
            | (b'i' as c_ulong) << 8
            | num
    }
    #[cfg(target_os = "openbsd")]
    const SIOCGIFRDOMAIN: c_ulong = iowr(160);
    #[cfg(target_os = "freebsd")]
    const SIOCGIFFIB: c_ulong = iowr(92);

    // Values from the system headers on 64-bit targets.
    #[cfg(all(target_os = "openbsd", target_pointer_width = "64"))]
    const _: () = assert!(SIOCGIFRDOMAIN == 0xc020_69a0);
    #[cfg(all(target_os = "freebsd", target_pointer_width = "64"))]
    const _: () = assert!(SIOCGIFFIB == 0xc020_695c);

    pub(super) fn set(socket: &SockRef<'_>, table: u32) -> io::Result<()> {
        super::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_RTABLE,
            &(table as c_int),
        )
    }

    /// Routing table of an interface, queried via any socket.
    pub(super) fn of_interface(socket: &SockRef<'_>, name: &str) -> io::Result<u32> {
        // SAFETY: all-zero is a valid `ifreq`.
        let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
        if name.len() >= req.ifr_name.len() || name.contains('\0') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid interface name",
            ));
        }
        for (dst, src) in req.ifr_name.iter_mut().zip(name.bytes()) {
            *dst = src as libc::c_char;
        }

        #[cfg(target_os = "openbsd")]
        let request = SIOCGIFRDOMAIN;
        #[cfg(target_os = "freebsd")]
        let request = SIOCGIFFIB;
        // SAFETY: valid fd, and `req` is a NUL-terminated `ifreq` that outlives the call.
        if unsafe { libc::ioctl(socket.as_raw_fd(), request, &mut req) } != 0 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: the kernel filled in this union member (`ifr_rdomainid` is `ifru_metric` on OpenBSD).
        #[cfg(target_os = "openbsd")]
        return Ok(unsafe { req.ifr_ifru.ifru_metric } as u32);
        #[cfg(target_os = "freebsd")]
        Ok(unsafe { req.ifr_ifru.ifru_fib })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{SocketAddrV6, TcpListener};

    const EXAMPLE: &[u8] = b"\x07example\x04test\0";
    const BIG: &[u8] = b"\x03big\x04test\0";
    const ADDR: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 7);
    const OK: [u8; 2] = [0x81, 0x80]; // QR, RD, RA

    #[test]
    fn scope_only_for_link_local() {
        let ll: SocketAddr = "[fe80::1]:53".parse().unwrap();
        let global: SocketAddr = "[2001:db8::1]:53".parse().unwrap();
        assert_eq!(
            with_scope(ll, 7),
            SocketAddr::V6(SocketAddrV6::new("fe80::1".parse().unwrap(), 53, 0, 7))
        );
        assert_eq!(with_scope(global, 7), global);
        assert_eq!(with_scope(ll, 0), ll);
    }

    #[test]
    fn builds_query() {
        let q = build_query(0x1234, EXAMPLE, TYPE_AAAA);
        assert_eq!(q[..12], [0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(q[12..26], *EXAMPLE);
        assert_eq!(q[26..], [0, 28, 0, 1]);
    }

    /// A response to `build_query(id, EXAMPLE, qtype)` claiming `ancount` records in `answers`.
    fn response(id: u16, flags: [u8; 2], qtype: u16, ancount: u16, answers: &[u8]) -> Vec<u8> {
        let mut msg = id.to_be_bytes().to_vec();
        msg.extend(flags);
        msg.extend([0, 1]);
        msg.extend(ancount.to_be_bytes());
        msg.extend([0, 0, 0, 0]);
        msg.extend_from_slice(EXAMPLE);
        msg.extend(qtype.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        msg.extend_from_slice(answers);
        msg
    }

    /// A record whose name is a pointer to the question's.
    fn record(rtype: u16, rdata: &[u8]) -> Vec<u8> {
        let mut r = vec![0xC0, 0x0C];
        r.extend(rtype.to_be_bytes());
        r.extend([0, 1, 0, 0, 0, 60]);
        r.extend((rdata.len() as u16).to_be_bytes());
        r.extend_from_slice(rdata);
        r
    }

    fn parse(msg: &[u8], qtype: u16) -> Result<Vec<IpAddr>, Failure> {
        parse_response(msg, 7, EXAMPLE, qtype)
    }

    #[test]
    fn parses_answers() {
        // A CNAME first, then the addresses, as recursive resolvers chain them.
        let mut answers = record(5, b"\x03www\x07example\x04test\0");
        answers.extend(record(TYPE_A, &ADDR.octets()));
        answers.extend(record(TYPE_A, &[192, 0, 2, 8]));
        let msg = response(7, OK, TYPE_A, 3, &answers);
        assert_eq!(
            parse(&msg, TYPE_A).unwrap(),
            vec![IpAddr::V4(ADDR), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 8))]
        );
        let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7);
        let msg = response(7, OK, TYPE_AAAA, 1, &record(TYPE_AAAA, &v6.octets()));
        assert_eq!(parse(&msg, TYPE_AAAA).unwrap(), vec![IpAddr::V6(v6)]);
        // NODATA.
        assert_eq!(
            parse(&response(7, OK, TYPE_AAAA, 0, &[]), TYPE_AAAA).unwrap(),
            Vec::<IpAddr>::new()
        );
    }

    #[test]
    fn rejects_mismatches() {
        let good = response(7, OK, TYPE_A, 1, &record(TYPE_A, &ADDR.octets()));
        assert!(parse(&good, TYPE_A).is_ok());
        assert!(matches!(parse(&good, TYPE_AAAA), Err(Failure::Other(_))));
        assert!(matches!(
            parse_response(&good, 8, EXAMPLE, TYPE_A),
            Err(Failure::Other(_))
        ));
        assert!(matches!(
            parse_response(&good, 7, b"\x05other\x04test\0", TYPE_A),
            Err(Failure::Other(_))
        ));
        // A query, not a response.
        assert!(parse(&response(7, [0x01, 0x00], TYPE_A, 0, &[]), TYPE_A).is_err());
        // Name case does not matter.
        let mut upper = good.clone();
        upper[13..20].make_ascii_uppercase();
        assert!(parse(&upper, TYPE_A).is_ok());
    }

    #[test]
    fn rcodes() {
        let nxdomain = response(7, [0x81, 0x83], TYPE_A, 0, &[]);
        assert!(matches!(parse(&nxdomain, TYPE_A), Err(Failure::NoSuchName)));
        let servfail = response(7, [0x81, 0x82], TYPE_A, 0, &[]);
        assert!(matches!(parse(&servfail, TYPE_A), Err(Failure::Other(_))));
    }

    #[test]
    fn rejects_malformed() {
        let a = record(TYPE_A, &ADDR.octets());
        // Record cut short.
        assert!(parse(&response(7, OK, TYPE_A, 1, &a[..a.len() - 1]), TYPE_A).is_err());
        // Answer count beyond the message.
        assert!(parse(&response(7, OK, TYPE_A, 2, &a), TYPE_A).is_err());
        // Pointer cut short.
        assert!(parse(&response(7, OK, TYPE_A, 1, &[0xC0]), TYPE_A).is_err());
        // Wrong address length.
        let short = record(TYPE_A, &[1, 2, 3]);
        assert!(parse(&response(7, OK, TYPE_A, 1, &short), TYPE_A).is_err());
        // Header only.
        assert!(parse(&[0, 7, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0], TYPE_A).is_err());
        assert_eq!(skip_name(b"\x01a\x40", 0), None); // reserved label type
        assert_eq!(skip_name(b"\x01a", 0), None); // no root label
        assert_eq!(skip_name(b"\x01a\xC0\x0C", 0), Some(4));
    }

    /// A reply from the fake server: `example.test` has 192.0.2.7, `big.test` three addresses
    /// (truncated over UDP), `nx.test` does not exist, other names have no records.
    fn answer(query: &[u8], tcp: bool, servfail: bool) -> Vec<u8> {
        let name_end = 12 + query[12..].iter().position(|&b| b == 0).unwrap() + 1;
        let qname = &query[12..name_end];
        let qtype = u16::from_be_bytes([query[name_end], query[name_end + 1]]);
        let truncated = !tcp && qname == BIG;
        let rcode = match (servfail, qname) {
            (true, _) => 2,
            (false, b"\x02nx\x04test\0") => RCODE_NXDOMAIN,
            _ => 0,
        };
        let addrs: &[Ipv4Addr] = match (qname, qtype, truncated || rcode != 0) {
            (EXAMPLE, TYPE_A, false) => &[ADDR],
            (BIG, TYPE_A, false) => &[
                Ipv4Addr::new(192, 0, 2, 1),
                Ipv4Addr::new(192, 0, 2, 2),
                Ipv4Addr::new(192, 0, 2, 3),
            ],
            _ => &[],
        };
        let mut msg = query[..2].to_vec();
        msg.extend([0x81 | if truncated { FLAG_TC } else { 0 }, 0x80 | rcode]);
        msg.extend([0, 1]);
        msg.extend((addrs.len() as u16).to_be_bytes());
        msg.extend([0, 0, 0, 0]);
        msg.extend_from_slice(&query[12..name_end + 4]);
        for a in addrs {
            msg.extend(record(TYPE_A, &a.octets()));
        }
        msg
    }

    /// A nameserver on UDP and TCP at one loopback port; see [`answer`].
    fn fake_server(servfail: bool) -> SocketAddr {
        let (udp, tcp) = loop {
            let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
            if let Ok(udp) = UdpSocket::bind(tcp.local_addr().unwrap()) {
                break (udp, tcp);
            }
        };
        let addr = tcp.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok((len, src)) = udp.recv_from(&mut buf) {
                udp.send_to(&answer(&buf[..len], false, servfail), src)
                    .unwrap();
            }
        });
        std::thread::spawn(move || {
            for stream in tcp.incoming() {
                let mut stream = stream.unwrap();
                let mut len = [0u8; 2];
                stream.read_exact(&mut len).unwrap();
                let mut query = vec![0u8; usize::from(u16::from_be_bytes(len))];
                stream.read_exact(&mut query).unwrap();
                let reply = answer(&query, true, servfail);
                stream
                    .write_all(&[&(reply.len() as u16).to_be_bytes()[..], &reply].concat())
                    .unwrap();
            }
        });
        addr
    }

    fn lookup(config: &StaticResolverConfig, name: &str) -> io::Result<Vec<IpAddr>> {
        config.lookup(&name.parse().unwrap())
    }

    #[test]
    fn lookup_via_udp() {
        let config = StaticResolverConfig::new([fake_server(false)]);
        assert_eq!(
            lookup(&config, "example.test").unwrap(),
            vec![IpAddr::V4(ADDR)]
        );
        let nxdomain = lookup(&config, "nx.test").unwrap_err();
        assert_eq!(nxdomain.kind(), io::ErrorKind::NotFound);
        let nodata = lookup(&config, "nodata.test").unwrap_err();
        assert_eq!(nodata.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn truncation_falls_back_to_tcp() {
        let config = StaticResolverConfig::new([fake_server(false)]);
        assert_eq!(lookup(&config, "big.test").unwrap().len(), 3);
    }

    #[test]
    fn failing_server_is_skipped() {
        let config = StaticResolverConfig::new([fake_server(true), fake_server(false)]);
        assert_eq!(
            lookup(&config, "example.test").unwrap(),
            vec![IpAddr::V4(ADDR)]
        );
    }

    #[test]
    fn no_nameservers() {
        let config = StaticResolverConfig::new(std::iter::empty());
        assert!(lookup(&config, "example.test").is_err());
    }

    #[test]
    fn time_bound() {
        assert_eq!(query_time_bound(2), Duration::from_secs(20));
        // Saturates instead of overflowing.
        assert!(query_time_bound(usize::MAX) > Duration::from_secs(20));
    }
}
