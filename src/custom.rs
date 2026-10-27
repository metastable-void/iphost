//! Custom DNS resolvers (`custom` feature), backed by hickory-resolver.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{OnceLock, mpsc};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use fqdn::FQDN;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::iocompat::AsyncIoTokioAsStd;
use hickory_resolver::net::runtime::{
    DnsUdpSocket, RuntimeProvider, TokioHandle, TokioRuntimeProvider, TokioTime,
};
use hickory_resolver::proto::rr::Name;
use socket2::{Domain, Protocol, SockRef, Socket, Type};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

/// Same as hickory's default.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

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
    /// The interface is looked up on every connection, so a recreated interface is picked up.
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
    /// Nameservers to query over UDP (falling back to TCP), usually on port 53.
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

    /// Blocking lookup on our own runtime threads, so it never panics in (or outside) a tokio context.
    pub(crate) fn lookup(&self, fqdn: &FQDN) -> io::Result<Vec<IpAddr>> {
        let mut name = Name::from_ascii(fqdn.to_string()).map_err(io::Error::other)?;
        name.set_fqdn(true);

        let servers = self
            .nameservers
            .iter()
            .map(|addr| {
                let mut ns = NameServerConfig::udp_and_tcp(addr.ip());
                for conn in &mut ns.connections {
                    conn.port = addr.port();
                }
                ns
            })
            .collect();
        let config = ResolverConfig::from_name_servers(servers);
        let provider = Provider {
            inner: TokioRuntimeProvider::new(),
            config: self.clone(),
        };

        let (tx, rx) = mpsc::sync_channel(1);
        runtime()?.spawn(async move {
            // shortcut: a fresh resolver per lookup means no hickory cache; keep one per config if query volume matters.
            // Built inside the runtime: hickory spawns background tasks on build.
            let res =
                match hickory_resolver::Resolver::builder_with_config(config, provider).build() {
                    Ok(resolver) => resolver.lookup_ip(name).await,
                    Err(e) => Err(e),
                };
            let _ = tx.send(res.map(|lookup| lookup.iter().collect()));
        });
        rx.recv()
            .map_err(|_| io::Error::other("resolver task panicked"))?
            .map_err(io::Error::other)
    }
}

/// Shared multi-threaded runtime on our own threads, created on first use.
fn runtime() -> io::Result<&'static tokio::runtime::Runtime> {
    static RUNTIME: OnceLock<io::Result<tokio::runtime::Runtime>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_name("iphost-resolver")
                .enable_all()
                .build()
        })
        .as_ref()
        .map_err(|e| io::Error::new(e.kind(), e.to_string()))
}

/// `setsockopt(2)` with an `int` value, for options socket2 lacks.
#[cfg(unix)]
pub(crate) fn setsockopt_int(
    fd: std::os::fd::RawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    // SAFETY: `value` outlives the call with the given length.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            (&raw const value).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
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

#[cfg(not(unix))]
pub(crate) fn if_index(_name: &str) -> io::Result<u32> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "interface binding is not supported on this platform",
    ))
}

/// Sets `scope_id` on link-local IPv6 targets that lack one. hickory drops scope IDs of nameservers.
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

/// hickory runtime provider that binds sockets to a device and restores nameserver scope IDs.
#[derive(Clone)]
struct Provider {
    inner: TokioRuntimeProvider,
    config: StaticResolverConfig,
}

impl Provider {
    /// Scope ID for a nameserver: the configured one, else the bound interface's index for link-local addresses.
    fn scope_id(&self, server: SocketAddr) -> io::Result<u32> {
        let SocketAddr::V6(server) = server else {
            return Ok(0);
        };
        if !server.ip().is_unicast_link_local() {
            return Ok(0);
        }
        let configured = self.config.nameservers.iter().find_map(|addr| match addr {
            SocketAddr::V6(addr) if addr.ip() == server.ip() && addr.scope_id() != 0 => {
                Some(addr.scope_id())
            }
            _ => None,
        });
        match (configured, &self.config.bind_device) {
            (Some(scope_id), _) => Ok(scope_id),
            (None, Some(BindDevice::Interface(name))) => if_index(name),
            _ => Ok(0),
        }
    }

    fn bind_device(&self, socket: SockRef<'_>, ipv6: bool) -> io::Result<()> {
        let _ = (&socket, ipv6);
        match &self.config.bind_device {
            None => Ok(()),
            #[cfg(target_os = "linux")]
            Some(BindDevice::Interface(name) | BindDevice::Vrf(name)) => {
                socket.bind_device(Some(name.as_bytes()))
            }
            #[cfg(any(target_vendor = "apple", target_os = "illumos", target_os = "solaris"))]
            Some(BindDevice::Interface(name)) => {
                let index = std::num::NonZeroU32::new(if_index(name)?);
                if ipv6 {
                    socket.bind_device_by_index_v6(index)
                } else {
                    socket.bind_device_by_index_v4(index)
                }
            }
            #[cfg(any(target_os = "openbsd", target_os = "freebsd"))]
            Some(BindDevice::Interface(name)) => {
                rtable::set(&socket, rtable::of_interface(&socket, name)?)
            }
            #[cfg(any(target_os = "openbsd", target_os = "freebsd"))]
            Some(BindDevice::Vrf(table)) => rtable::set(
                &socket,
                table.parse().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "VRF must be a routing table number",
                    )
                })?,
            ),
            #[cfg(not(any(
                target_os = "linux",
                target_vendor = "apple",
                target_os = "illumos",
                target_os = "solaris",
                target_os = "openbsd",
                target_os = "freebsd"
            )))]
            Some(BindDevice::Interface(_)) => Ok(()),
        }
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
        super::setsockopt_int(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_RTABLE,
            table as c_int,
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

impl RuntimeProvider for Provider {
    type Handle = TokioHandle;
    type Timer = TokioTime;
    type Udp = ScopedUdpSocket;
    type Tcp = AsyncIoTokioAsStd<TcpStream>;

    fn create_handle(&self) -> Self::Handle {
        self.inner.create_handle()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
        let this = self.clone();
        Box::pin(async move {
            let server_addr = with_scope(server_addr, this.scope_id(server_addr)?);
            let socket = match server_addr {
                SocketAddr::V4(_) => TcpSocket::new_v4(),
                SocketAddr::V6(_) => TcpSocket::new_v6(),
            }?;
            this.bind_device(SockRef::from(&socket), server_addr.is_ipv6())?;
            if let Some(bind_addr) = bind_addr {
                socket.bind(bind_addr)?;
            }
            socket.set_nodelay(true)?;
            let stream = tokio::time::timeout(
                timeout.unwrap_or(CONNECT_TIMEOUT),
                socket.connect(server_addr),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP connect timed out"))??;
            Ok(AsyncIoTokioAsStd(stream))
        })
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Udp>>>> {
        let this = self.clone();
        Box::pin(async move {
            let socket = Socket::new(
                Domain::for_address(local_addr),
                Type::DGRAM,
                Some(Protocol::UDP),
            )?;
            this.bind_device(SockRef::from(&socket), local_addr.is_ipv6())?;
            socket.set_nonblocking(true)?;
            socket.bind(&local_addr.into())?;
            Ok(ScopedUdpSocket {
                socket: UdpSocket::from_std(socket.into())?,
                scope_id: this.scope_id(server_addr)?,
            })
        })
    }
}

/// UDP socket that applies a scope ID to link-local targets.
struct ScopedUdpSocket {
    socket: UdpSocket,
    scope_id: u32,
}

impl DnsUdpSocket for ScopedUdpSocket {
    type Time = TokioTime;

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let mut buf = tokio::io::ReadBuf::new(buf);
        let addr = ready!(self.socket.poll_recv_from(cx, &mut buf))?;
        Poll::Ready(Ok((buf.filled().len(), addr)))
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        self.socket
            .poll_send_to(cx, buf, with_scope(target, self.scope_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::proto::op::{Message, OpCode};
    use hickory_resolver::proto::rr::rdata::A;
    use hickory_resolver::proto::rr::{RData, Record, RecordType};
    use std::net::{Ipv4Addr, SocketAddrV6};

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

    /// Answers A queries with 192.0.2.7 and everything else with no records.
    fn fake_dns_server() -> SocketAddr {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok((len, src)) = socket.recv_from(&mut buf) {
                let query = Message::from_vec(&buf[..len]).unwrap();
                let mut resp = Message::response(query.metadata.id, OpCode::Query);
                resp.metadata.recursion_desired = query.metadata.recursion_desired;
                resp.metadata.recursion_available = true;
                for q in &query.queries {
                    resp.add_query(q.clone());
                    if q.query_type() == RecordType::A {
                        resp.add_answer(Record::from_rdata(
                            q.name().clone(),
                            60,
                            RData::A(A(Ipv4Addr::new(192, 0, 2, 7))),
                        ));
                    }
                }
                socket.send_to(&resp.to_vec().unwrap(), src).unwrap();
            }
        });
        addr
    }

    #[test]
    fn lookup_via_static_resolver() {
        let config = StaticResolverConfig::new([fake_dns_server()]);
        let addrs = config.lookup(&"example.test".parse().unwrap()).unwrap();
        assert_eq!(addrs, vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))]);
    }

    #[test]
    fn lookup_inside_spawn_blocking() {
        let config = StaticResolverConfig::new([fake_dns_server()]);
        let rt = tokio::runtime::Builder::new_multi_thread().build().unwrap();
        let addrs = rt
            .block_on(async {
                tokio::task::spawn_blocking(move || config.lookup(&"example.test".parse().unwrap()))
                    .await
            })
            .unwrap()
            .unwrap();
        assert_eq!(addrs, vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))]);
    }
}
