// SPDX-License-Identifier: AGPL-3.0-or-later

//! Full reachability sweep against declared topology.
//! Pings every gate IP (LAN + WG overlay) and infrastructure devices.

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

use metalforge_types::device::DeviceRegistry;
use metalforge_types::probe::{ProbeCategory, ProbeCheck, ProbeMeta, ProbeResult, ProbeStatus};

use crate::registry::Probe;

/// Known gate LAN IPs (from `TOPOLOGY_MAP` + manifest).
/// These will be loaded from manifest in the future; hardcoded for bootstrap.
const TOPOLOGY_TARGETS: &[(&str, &str)] = &[
    ("sporeGate (LAN)", "192.168.4.1"),
    ("eastGate (WG)", "10.13.37.5"),
    ("ironGate (WG)", "10.13.37.7"),
    ("golgiBody (WG)", "10.13.37.1"),
    ("flockGate (WG)", "10.13.37.6"),
];

pub struct TopologySweepProbe {
    meta: ProbeMeta,
    device_targets: Vec<(String, String)>,
}

impl TopologySweepProbe {
    #[must_use]
    pub fn new(device_registry: &DeviceRegistry) -> Self {
        let device_targets: Vec<(String, String)> = device_registry
            .devices
            .iter()
            .filter(|(_, spec)| spec.ip != "0.0.0.0")
            .map(|(name, spec)| (name.clone(), spec.ip.clone()))
            .collect();

        Self {
            meta: ProbeMeta {
                id: "topology-sweep",
                category: ProbeCategory::Network,
                description: "ICMP reachability sweep of all declared gates and devices",
                target: "all",
                supports_remediation: false,
            },
            device_targets,
        }
    }

    async fn probe_impl(&self) -> ProbeResult {
        let start = Instant::now();
        let mut checks = Vec::new();

        for (name, ip) in TOPOLOGY_TARGETS {
            let (reachable, latency) = icmp_ping(ip).await;
            checks.push(ProbeCheck {
                name: format!("{name} ({ip})"),
                status: if reachable {
                    ProbeStatus::Pass
                } else {
                    ProbeStatus::Unreachable
                },
                detail: latency.map(|l| format!("{:.1}ms", l.as_secs_f64() * 1000.0)),
                latency,
            });
        }

        for (name, ip) in &self.device_targets {
            let (reachable, latency) = icmp_ping(ip).await;
            checks.push(ProbeCheck {
                name: format!("{name} ({ip})"),
                status: if reachable {
                    ProbeStatus::Pass
                } else {
                    ProbeStatus::Unreachable
                },
                detail: latency.map(|l| format!("{:.1}ms", l.as_secs_f64() * 1000.0)),
                latency,
            });
        }

        let any_fail = checks.iter().any(|c| !c.status.is_healthy());
        let all_unreachable = checks.iter().all(|c| c.status == ProbeStatus::Unreachable);

        let status = if all_unreachable {
            ProbeStatus::Unreachable
        } else if any_fail {
            ProbeStatus::Fail
        } else {
            ProbeStatus::Pass
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

impl Probe for TopologySweepProbe {
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

/// ICMP ping using the system `ping` command (works without raw socket privileges).
async fn icmp_ping(ip: &str) -> (bool, Option<Duration>) {
    let start = Instant::now();
    let result = tokio::process::Command::new("ping")
        .args(["-c", "1", "-W", "3", ip])
        .output()
        .await;

    match result {
        Ok(output) if output.status.success() => (true, Some(start.elapsed())),
        _ => (false, None),
    }
}
