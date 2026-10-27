#!/bin/sh
# Runs tests/linux_bind.rs (interface / VRF binding) in a privileged Docker container.
# Usage: tests/linux-bind.sh
set -eu

if [ "${1:-}" = "--inside" ]; then
    apk add --no-cache iproute2 dnsmasq >/dev/null

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

    # ve0 <-> ve1 (netns peer): 10.99.0.0/24 and fe80::2. dummy0 leads nowhere.
    ip netns add peer
    ip link add ve0 type veth peer name ve1 netns peer
    ip link add dummy0 type dummy
    ip addr add 10.99.0.1/24 dev ve0
    ip link set ve0 up
    ip link set dummy0 up
    at peer ip addr add 10.99.0.2/24 dev ve1
    at peer ip addr add fe80::2/64 dev ve1 nodad
    at peer ip link set ve1 up

    # ve2 (in vrf-blue) <-> ve3 (netns peer2): 10.98.0.0/24, routed only in VRF table 10.
    ip link add vrf-blue type vrf table 10
    ip link set vrf-blue up
    ip netns add peer2
    ip link add ve2 type veth peer name ve3 netns peer2
    ip link set ve2 master vrf-blue
    ip addr add 10.98.0.1/24 dev ve2
    ip link set ve2 up
    at peer2 ip addr add 10.98.0.2/24 dev ve3
    at peer2 ip link set ve3 up

    dns() {
        at "$1" dnsmasq --no-resolv --no-hosts --addn-hosts=/tmp/big.hosts \
            --address="/example.test/$3" --interface="$2" --bind-interfaces \
            --user=root --pid-file="/run/dnsmasq-$1.pid" --edns-packet-max=512
    }
    dns peer ve1 192.0.2.7
    dns peer2 ve3 192.0.2.8
    sleep 1

    exec /test/linux_bind --ignored --test-threads=1
fi

cd "$(dirname "$0")/.."
target=x86_64-unknown-linux-musl
bin=$(cargo test --target "$target" --features custom --test linux_bind --no-run 2>&1 |
    sed -n 's/.*Executable .*(\(.*\))$/\1/p')
if [ -z "$bin" ]; then
    echo "linux-bind.sh: failed to build the test binary" >&2
    exit 1
fi

docker run --rm --privileged \
    -v "$PWD/tests/linux-bind.sh:/test/run.sh:ro" \
    -v "$PWD/$bin:/test/linux_bind:ro" \
    alpine:3.24 /bin/sh /test/run.sh --inside
