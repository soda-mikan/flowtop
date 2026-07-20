# Metrics and recording schema

## TCP

Linux TCP state numbers are converted directly to `TcpState`. eBPF-classified established sockets are
split into accepted and connected. The current total from `/proc/net/tcp*` remains authoritative for
the host snapshot; its unclassified remainder is Unknown. The proc backend has no confirmed direction,
so Accepted and Connected are unavailable rather than zero.

Opened/accepted/connected/closed per-second values are derived from lifecycle-event counters in eBPF
mode and are unavailable in proc mode. `opened_per_sec` is the total of accepted inbound and connected
outbound events. The TUI graphs the directional `Accept/s` and `Connect/s` rates separately, alongside
`Close/s`, so connections that begin and end between snapshots remain visible as activity.

## Rates

Network, disk, process I/O, and CPU values are derived from consecutive absolute counters and the
monotonic elapsed time. A decreasing `u64` counter is treated as a wrap. The first snapshot reports
zero host rates and unavailable event rates because it has no baseline.

Host network rates are interface bytes. Process network rates are reserved fields and currently
unavailable. Disk statistics use 512 bytes per reported sector, as defined for Linux diskstats.

## JSON Lines

The first record is `record_type=metadata`; later lines are `record_type=snapshot`. Every line contains
`schema_version=1`. JSON represents unavailable optional metrics as `null`.

## CSV

CSV has a stable header and one row per snapshot. Optional metrics are empty fields. Use JSONL when
embedded run labels and full metadata are required.
