//! Linux interface / VRF binding and RA tests. They need the network set up by `tests/linux-bind.sh`,
//! which runs them in a privileged Docker container.
#![cfg(all(target_os = "linux", feature = "custom"))]

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV6};

use iphost::{BindDevice, IpHost, IpHostResolver, Resolver, StaticResolverConfig};

/// dnsmasq behind `ve0` answers this; the one behind `vrf-blue` answers 192.0.2.8.
const VIA_INTERFACE: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
const VIA_VRF: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 8));

fn resolve(name: &str, config: StaticResolverConfig) -> Vec<IpAddr> {
    // No cache fallback, so errors show up as an empty result.
    IpHostResolver::new_with_config(name.parse::<IpHost>().unwrap(), false, false)
        .with_resolver(Resolver::Static(config))
        .resolve()
}

fn link_local_ns(scope_id: u32) -> SocketAddr {
    SocketAddrV6::new("fe80::2".parse().unwrap(), 53, 0, scope_id).into()
}

fn ifindex(name: &str) -> u32 {
    std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

#[test]
#[ignore = "needs tests/linux-bind.sh"]
fn interface_global_nameserver() {
    let config = StaticResolverConfig::new(["10.99.0.2:53".parse().unwrap()])
        .with_bind_device(BindDevice::Interface("ve0".into()));
    assert_eq!(resolve("example.test", config), vec![VIA_INTERFACE]);
}

#[test]
#[ignore = "needs tests/linux-bind.sh"]
fn wrong_interface_fails() {
    let config = StaticResolverConfig::new(["10.99.0.2:53".parse().unwrap()])
        .with_bind_device(BindDevice::Interface("dummy0".into()));
    assert!(resolve("example.test", config).is_empty());
}

#[test]
#[ignore = "needs tests/linux-bind.sh"]
fn link_local_scope_from_interface() {
    let config = StaticResolverConfig::new([link_local_ns(0)])
        .with_bind_device(BindDevice::Interface("ve0".into()));
    assert_eq!(resolve("example.test", config), vec![VIA_INTERFACE]);
}

#[test]
#[ignore = "needs tests/linux-bind.sh"]
fn link_local_explicit_scope() {
    let config = StaticResolverConfig::new([link_local_ns(ifindex("ve0"))]);
    assert_eq!(resolve("example.test", config), vec![VIA_INTERFACE]);
}

#[test]
#[ignore = "needs tests/linux-bind.sh"]
fn link_local_without_scope_fails() {
    let config = StaticResolverConfig::new([link_local_ns(0)]);
    assert!(resolve("example.test", config).is_empty());
}

/// `big.test` has 200 A records and dnsmasq caps UDP at 512 bytes, so this only passes over TCP.
#[test]
#[ignore = "needs tests/linux-bind.sh"]
fn link_local_tcp_fallback() {
    let config = StaticResolverConfig::new([link_local_ns(0)])
        .with_bind_device(BindDevice::Interface("ve0".into()));
    assert_eq!(resolve("big.test", config).len(), 200);
}

#[test]
#[ignore = "needs tests/linux-bind.sh"]
fn vrf() {
    let config = StaticResolverConfig::new(["10.98.0.2:53".parse().unwrap()])
        .with_bind_device(BindDevice::Vrf("vrf-blue".into()));
    assert_eq!(resolve("example.test", config), vec![VIA_VRF]);
}

#[test]
#[ignore = "needs tests/linux-bind.sh"]
fn vrf_tcp_fallback() {
    let config = StaticResolverConfig::new(["10.98.0.2:53".parse().unwrap()])
        .with_bind_device(BindDevice::Vrf("vrf-blue".into()));
    assert_eq!(resolve("big.test", config).len(), 200);
}

/// The VRF's routes are not in the main table.
#[test]
#[ignore = "needs tests/linux-bind.sh"]
fn vrf_unbound_fails() {
    let config = StaticResolverConfig::new(["10.98.0.2:53".parse().unwrap()]);
    assert!(resolve("example.test", config).is_empty());
}

/// Run twice by the script: as root with `accept_ra=0` and a router that only answers
/// solicitations (raw socket path), and as nobody with `accept_ra=2` and periodic RAs (netlink path).
#[cfg(feature = "ra")]
#[test]
#[ignore = "needs tests/linux-bind.sh"]
fn ra_resolver() {
    use std::time::{Duration, Instant};

    let config = iphost::RaResolverConfig::new("ve0").unwrap();
    let resolver = IpHostResolver::new_with_config("example.test".parse().unwrap(), false, false)
        .with_resolver(Resolver::Ra(config.clone()));
    let deadline = Instant::now() + Duration::from_secs(20);
    // Each attempt waits a few seconds for the first RA.
    let addrs = loop {
        let addrs = resolver.resolve();
        if !addrs.is_empty() || Instant::now() > deadline {
            break addrs;
        }
    };
    assert_eq!(addrs, vec![VIA_INTERFACE]);
    assert_eq!(
        config.nameservers(),
        vec!["2001:db8:99::2".parse::<std::net::Ipv6Addr>().unwrap()]
    );
}

/// The DHCPv6 server hands out the link-local DNS server fe80::2, and echoes our Client Identifier.
#[cfg(feature = "dhcpv6")]
fn dhcpv6_resolver(client_id: iphost::ClientId) {
    let config = iphost::Dhcpv6ResolverConfig::new("ve0", client_id).unwrap();
    let resolver = IpHostResolver::new_with_config("example.test".parse().unwrap(), false, false)
        .with_resolver(Resolver::Dhcpv6(config.clone()));
    assert_eq!(resolver.resolve(), vec![VIA_INTERFACE]);
    assert_eq!(
        config.nameservers(),
        vec!["fe80::2".parse::<std::net::Ipv6Addr>().unwrap()]
    );
}

#[cfg(feature = "dhcpv6")]
#[test]
#[ignore = "needs tests/linux-bind.sh"]
fn dhcpv6_anonymous() {
    dhcpv6_resolver(iphost::ClientId::None);
}

#[cfg(feature = "dhcpv6")]
#[test]
#[ignore = "needs tests/linux-bind.sh"]
fn dhcpv6_duid_ll() {
    let mac = std::fs::read_to_string("/sys/class/net/ve0/address").unwrap();
    let mac: Vec<u8> = mac
        .trim()
        .split(':')
        .map(|b| u8::from_str_radix(b, 16).unwrap())
        .collect();
    dhcpv6_resolver(iphost::ClientId::DuidLl(mac.try_into().unwrap()));
}

#[cfg(feature = "dhcpv6")]
#[test]
#[ignore = "needs tests/linux-bind.sh"]
fn dhcpv6_random_duid_ll() {
    dhcpv6_resolver(iphost::ClientId::RandomDuidLl);
}

/// Waits until every config has DNS servers, returning them.
#[cfg(feature = "dhcpv6")]
fn wait_dhcpv6(configs: &[&iphost::Dhcpv6ResolverConfig]) -> Vec<Vec<std::net::Ipv6Addr>> {
    use std::time::{Duration, Instant};

    let deadline = Instant::now() + Duration::from_secs(10);
    while configs.iter().any(|c| c.nameservers().is_empty()) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    configs.iter().map(|c| c.nameservers()).collect()
}

/// Many DHCPv6 clients at once, on the same interface and on another one (in a VRF), must not
/// take each other's Replies.
#[cfg(feature = "dhcpv6")]
#[test]
#[ignore = "needs tests/linux-bind.sh"]
fn dhcpv6_many_instances() {
    use iphost::{ClientId, Dhcpv6ResolverConfig};

    let a = Dhcpv6ResolverConfig::new("ve0", ClientId::None).unwrap();
    let b = Dhcpv6ResolverConfig::new("ve0", ClientId::RandomDuidLl).unwrap();
    let c = Dhcpv6ResolverConfig::new("ve0", ClientId::None).unwrap();
    let d = Dhcpv6ResolverConfig::new("ve2", ClientId::None).unwrap();
    let e = Dhcpv6ResolverConfig::new("ve2", ClientId::RandomDuidLl).unwrap();
    let ve0: Vec<std::net::Ipv6Addr> = vec!["fe80::2".parse().unwrap()];
    let ve2: Vec<std::net::Ipv6Addr> = vec!["2001:db8:98::2".parse().unwrap()];
    assert_eq!(
        wait_dhcpv6(&[&a, &b, &c, &d, &e]),
        [ve0.clone(), ve0.clone(), ve0, ve2.clone(), ve2]
    );
}

/// DHCPv6 on an interface enslaved to a VRF, with `udp_l3mdev_accept=0`.
#[cfg(feature = "dhcpv6")]
#[test]
#[ignore = "needs tests/linux-bind.sh"]
fn dhcpv6_vrf() {
    let config = iphost::Dhcpv6ResolverConfig::new("ve2", iphost::ClientId::None).unwrap();
    let resolver = IpHostResolver::new_with_config("example.test".parse().unwrap(), false, false)
        .with_resolver(Resolver::Dhcpv6(config));
    assert_eq!(resolver.resolve(), vec![VIA_VRF]);
}

/// RA on an interface enslaved to a VRF, with `raw_l3mdev_accept=0`.
#[cfg(feature = "ra")]
#[test]
#[ignore = "needs tests/linux-bind.sh"]
fn ra_vrf() {
    let config = iphost::RaResolverConfig::new("ve2").unwrap();
    let resolver = IpHostResolver::new_with_config("example.test".parse().unwrap(), false, false)
        .with_resolver(Resolver::Ra(config));
    assert_eq!(resolver.resolve(), vec![VIA_VRF]);
}

/// With both sources answering, DHCPv6 (fe80::2) takes precedence over RA (2001:db8:99::2).
#[cfg(all(feature = "ra", feature = "dhcpv6"))]
#[test]
#[ignore = "needs tests/linux-bind.sh"]
fn ipv6_prefers_dhcpv6() {
    use std::time::{Duration, Instant};

    let config = iphost::Ipv6ResolverConfig::new("ve0", iphost::ClientId::None).unwrap();
    let resolver = IpHostResolver::new_with_config("example.test".parse().unwrap(), false, false)
        .with_resolver(Resolver::Ipv6(config.clone()));
    assert_eq!(resolver.resolve(), vec![VIA_INTERFACE]);
    // RA may answer first; DHCPv6 wins as soon as both have.
    let deadline = Instant::now() + Duration::from_secs(5);
    while config.ra().unwrap().nameservers().is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(!config.ra().unwrap().nameservers().is_empty());
    assert_eq!(
        config.nameservers(),
        vec!["fe80::2".parse::<std::net::Ipv6Addr>().unwrap()]
    );
}

/// Run by the script as nobody with no DHCPv6 server: RA alone suffices.
#[cfg(all(feature = "ra", feature = "dhcpv6"))]
#[test]
#[ignore = "needs tests/linux-bind.sh"]
fn ipv6_ra_fallback() {
    use std::time::{Duration, Instant};

    let config = iphost::Ipv6ResolverConfig::new("ve0", iphost::ClientId::None).unwrap();
    let resolver = IpHostResolver::new_with_config("example.test".parse().unwrap(), false, false)
        .with_resolver(Resolver::Ipv6(config.clone()));
    let deadline = Instant::now() + Duration::from_secs(20);
    let addrs = loop {
        let addrs = resolver.resolve();
        if !addrs.is_empty() || Instant::now() > deadline {
            break addrs;
        }
    };
    assert_eq!(addrs, vec![VIA_INTERFACE]);
    assert_eq!(
        config.nameservers(),
        vec!["2001:db8:99::2".parse::<std::net::Ipv6Addr>().unwrap()]
    );
}

/// The resolver can be swapped at runtime.
#[test]
#[ignore = "needs tests/linux-bind.sh"]
fn swap_resolver() {
    let resolver = IpHostResolver::new_with_config("example.test".parse().unwrap(), false, false)
        .with_resolver(Resolver::Static(
            StaticResolverConfig::new(["10.99.0.2:53".parse().unwrap()])
                .with_bind_device(BindDevice::Interface("ve0".into())),
        ));
    assert_eq!(resolver.resolve(), vec![VIA_INTERFACE]);
    resolver.set_resolver(Resolver::Static(
        StaticResolverConfig::new(["10.98.0.2:53".parse().unwrap()])
            .with_bind_device(BindDevice::Vrf("vrf-blue".into())),
    ));
    assert_eq!(resolver.resolve(), vec![VIA_VRF]);
}
