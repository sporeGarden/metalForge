# metalForge

Hardware topology testing suite for the sporeGate ecosystem. Springs as a spore on hardware.

metalForge detects configuration drift, validates infrastructure health, and
auto-remediates known divergence patterns across all gates, switches, access
points, and network services in the topology.

## Ownership Boundary

| System | Owns |
|--------|------|
| **cellMembrane** | Code topology (transport resolution, gate profiles, manifest parsing) |
| **metalForge** | Hardware/deployment validation (does the physical world match the declared topology?) |
| **primalSpring** | Primal code testing (scenarios against live NUCLEUS compositions) |

## Quick Start

```bash
# List all registered probes
metalforge probe --list

# Run all probes (detect only)
metalforge probe --category all

# Run WiFi drift check with remediation
METALFORGE_WIFI_PSK=<psk> metalforge probe --category wifi --remediate

# Run specific category
metalforge probe --category wireguard

# Show full hardware inventory
metalforge inventory

# Quick status summary (runs all probes)
metalforge status

# JSON output for automation
metalforge probe --category all --json
```

## Probe Categories

| Category | Probes | What it validates |
|----------|--------|-------------------|
| `wifi` | `flint2-wifi-drift` | MediaTek .dat file SSID/auth/encryption match declared config |
| `network` | `topology-sweep`, `service-port-probe` | ICMP reachability + TCP port checks for all gates and devices |
| `wireguard` | `wg-handshake-freshness`, `wg-mesh-reachability` | Peer handshake age, transfer counters, overlay ping |
| `dns` | `dns-resolution` | Forward lookups, ad-blocking, DoT chain, dnsmasq/stubby process |
| `dhcp` | `dhcp-lease-audit` | Static hosts, range config, authoritative mode, blocklist loaded |

## Exit Codes

Matches primalSpring semantics:

- `0` — all probes pass (or remediated)
- `1` — one or more probes failed
- `2` — all probes skipped

## Configuration

### Device Registry

`config/device_registry.toml` declares all infrastructure hardware. Adding a new
device to monitor is a TOML entry, not a code change.

### Secrets

WiFi PSK and other secrets are never stored in the registry. Use environment variables:

- `METALFORGE_WIFI_PSK` — WiFi password for AP validation
- `METALFORGE_CONFIG_DIR` — Override config directory path

## Architecture

metalForge consumes `cellmembrane-types` for topology models (`TopologyMap`,
`GateProfile`, `NetworkSegment`) and reads from `TOPOLOGY_MAP.toml` and
`ecosystem_manifest.toml`. Probes use SSH (via the system `ssh` binary and
`~/.ssh/config`) for remote device access — no agents or daemons on targets.

## Building

```bash
cargo build --release
```

Requires Rust 1.85+ (edition 2024).

## License

AGPL-3.0-or-later
