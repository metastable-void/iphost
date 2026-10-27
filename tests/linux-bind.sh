#!/bin/sh
# Runs tests/linux_bind.rs (interface / VRF binding, RA, DHCPv6) in a privileged Docker container.
# Usage: tests/linux-bind.sh
set -eu

if [ "${1:-}" = "--inside" ]; then
    apk add --no-cache iproute2 dnsmasq radvd >/dev/null

    # No DAD, so link-local addresses are usable immediately.
    sysctl -qw net.ipv6.conf.all.accept_dad=0 net.ipv6.conf.default.accept_dad=0

    i=1
    while [ "$i" -le 200 ]; do
        echo "10.1.$((i / 256)).$((i % 256)) big.test"
        i=$((i + 1))
    done >/tmp/big.hosts

    # Runs a command in a netns. Not `ip -n` / `ip netns exec`: they remount /sys,
    # which fails in nested user namespaces.
    at() {
        ns=$1
        shift
        nsenter --net="/run/netns/$ns" "$@"
    }

    # New namespaces start with the default accept_dad; disable it there too, before creating
    # links, so their link-local addresses (which DHCPv6 servers need) are usable immediately.
    netns_add() {
        ip netns add "$1"
        at "$1" sysctl -qw net.ipv6.conf.all.accept_dad=0 net.ipv6.conf.default.accept_dad=0
    }

    # ve0 <-> ve1 (netns peer): 10.99.0.0/24, 2001:db8:99::/64 and fe80::2. dummy0 leads nowhere.
    netns_add peer
    ip link add ve0 type veth peer name ve1 netns peer
    ip link add dummy0 type dummy
    ip addr add 10.99.0.1/24 dev ve0
    ip addr add 2001:db8:99::1/64 dev ve0 nodad
    ip link set ve0 up
    ip link set dummy0 up
    at peer ip addr add 10.99.0.2/24 dev ve1
    at peer ip addr add 2001:db8:99::2/64 dev ve1 nodad
    at peer ip addr add fe80::2/64 dev ve1 nodad
    at peer ip link set ve1 up
    at peer sysctl -qw net.ipv6.conf.all.forwarding=1

    # ve2 (in vrf-blue) <-> ve3 (netns peer2): 10.98.0.0/24 and 2001:db8:98::/64, routed only
    # in VRF table 10.
    ip link add vrf-blue type vrf table 10
    ip link set vrf-blue up
    netns_add peer2
    ip link add ve2 type veth peer name ve3 netns peer2
    ip link set ve2 master vrf-blue
    ip addr add 10.98.0.1/24 dev ve2
    ip addr add 2001:db8:98::1/64 dev ve2 nodad
    ip link set ve2 up
    at peer2 ip addr add 10.98.0.2/24 dev ve3
    at peer2 ip addr add 2001:db8:98::2/64 dev ve3 nodad
    at peer2 ip link set ve3 up
    at peer2 sysctl -qw net.ipv6.conf.all.forwarding=1

    # Sockets not bound to a device must not see VRF traffic: the crate must not rely on these.
    sysctl -qw net.ipv4.udp_l3mdev_accept=0 net.ipv4.raw_l3mdev_accept=0

    dns() {
        at "$1" dnsmasq --no-resolv --no-hosts --addn-hosts=/tmp/big.hosts \
            --address="/example.test/$3" --interface="$2" --bind-interfaces \
            --user=root --pid-file="/run/dnsmasq-$1.pid" --edns-packet-max=512
    }
    dns peer ve1 192.0.2.7
    dns peer2 ve3 192.0.2.8

    # Stateless DHCPv6 servers: on ve1 handing out the link-local DNS server, and in the VRF.
    dhcpv6() {
        at "$1" dnsmasq --port=0 --interface="$2" --bind-interfaces --user=root \
            --pid-file="/run/dhcpv6-$1.pid" --dhcp-leasefile="/tmp/dhcpv6-$1.leases" \
            --dhcp-range="$3,static" "--dhcp-option=option6:dns-server,[$4]"
    }
    dhcpv6 peer ve1 2001:db8:99:: fe80::2
    dhcpv6 peer2 ve3 2001:db8:98:: 2001:db8:98::2

    # Routers advertising RDNSS. `UnicastOnly on`: answers solicitations only.
    radvd_start() {
        cat >"/tmp/radvd-$1.conf" <<EOF
interface $2 {
    AdvSendAdvert on;
    UnicastOnly $4;
    MinRtrAdvInterval 3;
    MaxRtrAdvInterval 4;
    AdvDefaultLifetime 0;
    RDNSS $3 { AdvRDNSSLifetime 60; };
};
EOF
        at "$1" radvd -C "/tmp/radvd-$1.conf" -p "/run/radvd-$1.pid"
    }

    # Raw socket path: root, the kernel ignores RAs, and RAs only come in reply to our solicitations.
    sysctl -qw net.ipv6.conf.ve0.accept_ra=0 net.ipv6.conf.ve2.accept_ra=0
    radvd_start peer ve1 2001:db8:99::2 on
    radvd_start peer2 ve3 2001:db8:98::2 on
    sleep 1
    /test/linux_bind --ignored --test-threads=1 --skip ipv6_ra_fallback

    # Netlink path: unprivileged, the kernel processes periodic RAs. No DHCPv6 server, so
    # Ipv6ResolverConfig falls back to RA.
    kill "$(cat /run/radvd-peer.pid)" "$(cat /run/dhcpv6-peer.pid)"
    sleep 1
    sysctl -qw net.ipv6.conf.ve0.accept_ra=2
    radvd_start peer ve1 2001:db8:99::2 off
    exec su -s /bin/sh nobody -c \
        '/test/linux_bind --ignored --test-threads=1 --exact ra_resolver ipv6_ra_fallback'
fi

cd "$(dirname "$0")/.."
target=x86_64-unknown-linux-musl
bin=$(cargo test --target "$target" --features ra,dhcpv6 --test linux_bind --no-run 2>&1 |
    sed -n 's/.*Executable .*(\(.*\))$/\1/p')
if [ -z "$bin" ]; then
    echo "linux-bind.sh: failed to build the test binary" >&2
    exit 1
fi

docker run --rm --privileged \
    -v "$PWD/tests/linux-bind.sh:/test/run.sh:ro" \
    -v "$PWD/$bin:/test/linux_bind:ro" \
    alpine:3.24 /bin/sh /test/run.sh --inside
