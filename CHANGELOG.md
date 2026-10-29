# Changelog

## 0.4.1 (unreleased)

### Protocol and deadline fixes

- RDNSS previously replaced the repository on most advertisements, so withdrawing A
  from an A+B list also removed B. It now updates addresses individually as specified
  by [RFC 8106 section 6.2](https://www.rfc-editor.org/rfc/rfc8106.html#section-6.2).
  Raw RAs and kernel options use the same update rules without a merge window.
  Invalid options cannot apply partial withdrawals. A 64-address limit bounds live
  and stale storage with deterministic eviction of omitted entries only, so a sender
  cannot pin the repository with infinite lifetimes; the three-server query limit stays.
  Stale fallback remains available, but explicitly withdrawn entries cannot return.
  Parsed-packet regressions cover withdrawals, refreshes, malformed input, multiple
  routers, delayed kernel messages, lifetimes, duplicates and capacity.
- UDP sends and partial TCP writes now use the query's absolute deadline, shared
  with UDP receives and TCP reads. No constructor or platform-binding API changes.
- Clarified that automatic resolver shutdown waits for an ongoing libc call in its
  worker, although dropping the resolver itself does not wait. System lookup bounds
  remain `None`; replacement still discards obsolete results.

### Additive failure-fallback policy

- Added `Ipv6ResolverConfig::with_failure_fallback(bool)`, defaulting to `false`.
  The README and `nameservers()` contract promise preferred-list selection; this
  release preserves that default. Opt-in lookups try DHCPv6 then RA independently
  for each family, only after failures. Definitive negative answers never fall
  through. Clones share discovery state; equality also compares the selected policy.
- The bound is 63 seconds with fallback and both sources started; selection-only
  and single-source configurations keep 33 seconds. Tests inject source lists,
  transport failures and virtual elapsed time, and exercise real UDP/TCP fallback,
  cache options, stable selection and generation invalidation.
- The shared query path now distinguishes OS `NotFound` failures (such as a missing
  interface on Windows) from negative DNS answers. A regression reproduced a cleared
  family cache after both sources reported that transport error; the cache now stays.
- No new dependencies, runtime requirements or daemon-specific restrictions.
  Existing constructors, features, cache defaults and interface/VRF support remain.
  Publishing and downstream adoption are separate steps; no rs-l2tpd integration
  gate is marked complete by these changes.
