# Security policy

## Scope

flowtop performs read-only observability. It does not capture packet payloads, TLS plaintext, HTTP
content, DNS names, credentials, or file contents, and it does not drop or modify traffic.

The snapshot recorder contains aggregate counters only. Do not add endpoints or process command lines
to the stable schema without a privacy review and explicit redaction controls.

## Privileges

Use root for development only when necessary. Production packaging should grant the smallest set of
capabilities demonstrated to work for the selected kernel and attach points. Capability requirements
vary by kernel; never silently retry with broader privileges.

The loader rejects unexpected tracepoint layouts. Shared eBPF structs have explicit layout, size
assertions, zero initialization, and reserved bytes to prevent uninitialized kernel memory disclosure.

## eBPF object trust

The kernel verifier checks bytecode safety, not the provenance of `flowtop-ebpf.o`. Treat the object
as privileged executable code and use only the object built for the same trusted flowtop release.
The loader searches `FLOWTOP_EBPF_OBJECT`, the directory containing the flowtop executable, and then
`/usr/lib/flowtop/flowtop-ebpf.o`, in that order.

For production installations, make `/usr/lib/flowtop` root-owned and non-writable by group or other
users (mode `0755`), and install `flowtop-ebpf.o` as `root:root` mode `0644`. The executable directory
must likewise not be writable by untrusted users. Do not preserve or inject an untrusted
`FLOWTOP_EBPF_OBJECT` value into a privileged flowtop process. Package managers should install the
binary and object atomically from the same signed package.

## Reporting

Report suspected vulnerabilities using GitHub's
[private vulnerability reporting](https://github.com/soda-mikan/flowtop/security/advisories/new).
Include the flowtop version, distribution, kernel version, backend, and a minimal reproduction. Do
not include captured secrets or unrelated host data in a public issue.
