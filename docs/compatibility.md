# Compatibility and Phase 0 risks

Initial targets are Ubuntu 22.04+, Debian 12+, Rocky Linux 9+, and AlmaLinux 9+ on x86_64 with Linux
5.15 or newer. aarch64 source compatibility is intended but its release artifact is not yet validated.

Kernel validation still required before declaring the eBPF backend production-ready:

- verifier load on 5.15, 6.1, and a current LTS kernel
- symbol availability for `tcp_v4_connect`, `tcp_v6_connect`, and `inet_csk_accept`
- `sock:inet_sock_set_state` format verification across distributions
- pointer-key reuse/churn tests and migration to socket-cookie identity
- PID attribution when state callbacks execute outside the initiating process context
- ring-buffer pressure, LRU capacity, and 100k concurrent socket tests
- IPv6 direction/state integration tests

If any attach or layout check fails, `--backend auto` reports the reason and starts the proc backend.
`--backend ebpf` or `--strict` turns the same condition into a startup error.

After building a release, run the load/attach smoke test as a privileged user on each validation
kernel and record the distribution, `uname -r`, architecture, flowtop version, and result:

```bash
sudo ./scripts/test-ebpf-smoke.sh
```

The smoke test requires the eBPF backend and therefore fails instead of falling back to proc. It is a
minimum load/attach check, not a substitute for the churn, pressure, attribution, and IPv6 tests above.

macOS and Windows are unsupported. The userspace code and parsers can be compiled/tested on macOS,
but `/proc` sampling and kernel attach tests require Linux.
