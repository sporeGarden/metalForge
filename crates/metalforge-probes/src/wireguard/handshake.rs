// SPDX-License-Identifier: AGPL-3.0-or-later

//! `WireGuard` peer handshake freshness probe.
//! Parses `wg show wg0` output to check latest handshake age and transfer counters.

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

use metalforge_types::probe::{ProbeCategory, ProbeCheck, ProbeMeta, ProbeResult, ProbeStatus};

use crate::registry::Probe;

/// Maximum age of a WG handshake before it's considered stale.
const HANDSHAKE_STALE_SECS: u64 = 180;

pub struct WgHandshakeProbe {
    meta: ProbeMeta,
}

impl Default for WgHandshakeProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl WgHandshakeProbe {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            meta: ProbeMeta {
                id: "wg-handshake-freshness",
                category: ProbeCategory::Wireguard,
                description: "WireGuard peer handshake age and transfer counters",
                target: "wg0",
                supports_remediation: false,
            },
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn probe_impl(&self) -> ProbeResult {
        let start = Instant::now();
        let mut checks = Vec::new();

        let wg_output = match tokio::process::Command::new("sudo")
            .args(["wg", "show", "wg0", "dump"])
            .output()
            .await
        {
            Ok(output) if output.status.success() => {
                String::from_utf8_lossy(&output.stdout).to_string()
            }
            Ok(output) => {
                checks.push(ProbeCheck {
                    name: "wg show wg0".to_string(),
                    status: ProbeStatus::Fail,
                    detail: Some(format!(
                        "wg show failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    )),
                    latency: None,
                });
                return build_result(&self.meta, ProbeStatus::Fail, checks, start.elapsed());
            }
            Err(e) => {
                checks.push(ProbeCheck {
                    name: "wg show wg0".to_string(),
                    status: ProbeStatus::Fail,
                    detail: Some(format!("failed to execute wg: {e}")),
                    latency: None,
                });
                return build_result(&self.meta, ProbeStatus::Fail, checks, start.elapsed());
            }
        };

        // wg show dump format: pubkey, preshared, endpoint, allowed-ips, handshake, rx, tx, keepalive
        // First line is the interface itself (private key, listen port, fwmark)
        let mut any_stale = false;

        for line in wg_output.lines().skip(1) {
            let fields: Vec<&str> = line.split('\t').collect();
            if fields.len() < 8 {
                continue;
            }

            let pubkey_short = &fields[0][..8.min(fields[0].len())];
            let endpoint = fields[2];
            let allowed_ips = fields[3];
            let handshake_epoch: u64 = fields[4].parse().unwrap_or(0);
            let rx_bytes: u64 = fields[5].parse().unwrap_or(0);
            let tx_bytes: u64 = fields[6].parse().unwrap_or(0);

            let now_epoch = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let handshake_age = if handshake_epoch > 0 {
                now_epoch.saturating_sub(handshake_epoch)
            } else {
                u64::MAX
            };

            let is_fresh = handshake_age < HANDSHAKE_STALE_SECS;
            let has_traffic = rx_bytes > 0 || tx_bytes > 0;

            let peer_label = format!("{pubkey_short}… ({allowed_ips})");

            if !is_fresh {
                any_stale = true;
            }

            checks.push(ProbeCheck {
                name: format!("{peer_label} handshake"),
                status: if is_fresh {
                    ProbeStatus::Pass
                } else {
                    ProbeStatus::Fail
                },
                detail: Some(if handshake_epoch == 0 {
                    "no handshake ever".to_string()
                } else {
                    format!("{handshake_age}s ago (threshold: {HANDSHAKE_STALE_SECS}s)")
                }),
                latency: None,
            });

            checks.push(ProbeCheck {
                name: format!("{peer_label} traffic"),
                status: if has_traffic {
                    ProbeStatus::Pass
                } else {
                    ProbeStatus::Drift
                },
                detail: Some(format!(
                    "rx={} tx={} endpoint={endpoint}",
                    human_bytes(rx_bytes),
                    human_bytes(tx_bytes)
                )),
                latency: None,
            });
        }

        if checks.is_empty() {
            checks.push(ProbeCheck {
                name: "wg0 peers".to_string(),
                status: ProbeStatus::Skipped,
                detail: Some("no peers configured".to_string()),
                latency: None,
            });
            return build_result(&self.meta, ProbeStatus::Skipped, checks, start.elapsed());
        }

        let status = if any_stale {
            ProbeStatus::Fail
        } else {
            ProbeStatus::Pass
        };

        build_result(&self.meta, status, checks, start.elapsed())
    }
}

impl Probe for WgHandshakeProbe {
    fn meta(&self) -> &ProbeMeta {
        &self.meta
    }

    fn run(
        &self,
        _remediate: bool,
        _dry_run: bool,
    ) -> Pin<Box<dyn Future<Output = ProbeResult> + Send + '_>> {
        Box::pin(self.probe_impl())
    }
}

fn build_result(
    meta: &ProbeMeta,
    status: ProbeStatus,
    checks: Vec<ProbeCheck>,
    elapsed: Duration,
) -> ProbeResult {
    ProbeResult {
        meta: meta.clone(),
        status,
        checks,
        timestamp: chrono::Utc::now().to_rfc3339(),
        elapsed,
        remediation_applied: false,
    }
}

#[allow(clippy::cast_precision_loss)]
fn human_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes}B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1}KiB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1}MiB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1}GiB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}
