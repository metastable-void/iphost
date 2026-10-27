//! Linux interface / VRF binding tests. They need the network set up by `tests/linux-bind.sh`,
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
