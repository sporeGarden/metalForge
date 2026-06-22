// SPDX-License-Identifier: AGPL-3.0-or-later

//! `WireGuard` mesh reachability — pings all overlay IPs through wg0.

use std::future::Future;
use std::pin::Pin;
use std::time::Instant;

use metalforge_types::probe::{ProbeCategory, ProbeCheck, ProbeMeta, ProbeResult, ProbeStatus};

use crate::registry::Probe;

/// WG overlay peers: (name, `wg_ip`).
/// Will be loaded from manifest in the future.
const WG_PEERS: &[(&str, &str)] = &[
    ("golgiBody", "10.13.37.1"),
    ("sporeGate", "10.13.37.2"),
    ("eastGate", "10.13.37.5"),
    ("flockGate", "10.13.37.6"),
    ("ironGate", "10.13.37.7"),
];

pub struct WgMeshReachabilityProbe {
    meta: ProbeMeta,
}

impl Default for WgMeshReachabilityProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl WgMeshReachabilityProbe {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            meta: ProbeMeta {
                id: "wg-mesh-reachability",
                category: ProbeCategory::Wireguard,
                description: "Ping all WireGuard overlay peers via wg0",
                target: "wg0",
                supports_remediation: false,
            },
        }
    }

    async fn probe_impl(&self) -> ProbeResult {
        let start = Instant::now();
        let mut checks = Vec::new();

        for (name, ip) in WG_PEERS {
            let ping_start = Instant::now();
            let result = tokio::process::Command::new("ping")
                .args(["-c", "1", "-W", "3", "-I", "wg0", ip])
                .output()
                .await;

            let (reachable, latency) = match result {
                Ok(output) if output.status.success() => (true, Some(ping_start.elapsed())),
                _ => (false, None),
            };

            checks.push(ProbeCheck {
                name: format!("{name} ({ip})"),
                status: if reachable {
                    ProbeStatus::Pass
                } else {
                    ProbeStatus::Unreachable
                },
                detail: latency.map(|l| format!("{:.1}ms RTT", l.as_secs_f64() * 1000.0)),
                latency,
            });
        }

        let all_pass = checks.iter().all(|c| c.status.is_healthy());
        let all_unreachable = checks.iter().all(|c| c.status == ProbeStatus::Unreachable);

        let status = if all_unreachable {
            ProbeStatus::Unreachable
        } else if all_pass {
            ProbeStatus::Pass
        } else {
            ProbeStatus::Fail
        };

        ProbeResult {
            meta: self.meta.clone(),
            status,
            checks,
            timestamp: chrono::Utc::now().to_rfc3339(),
            elapsed: start.elapsed(),
            remediation_applied: false,
        }
    }
}

impl Probe for WgMeshReachabilityProbe {
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
