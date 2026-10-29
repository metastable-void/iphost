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
