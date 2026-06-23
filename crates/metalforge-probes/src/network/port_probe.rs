// SPDX-License-Identifier: AGPL-3.0-or-later

//! TCP port probe for known services across the topology.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::{Duration, Instant};

use metalforge_types::probe::{ProbeCategory, ProbeCheck, ProbeMeta, ProbeResult, ProbeStatus};

use crate::registry::Probe;

/// Known service endpoints to probe (gate, ip, port, service name).
/// Only network-facing services — UDS-only primals (nestGate, etc.) are
/// validated by primalSpring, not metalForge.
const SERVICE_ENDPOINTS: &[(&str, &str, u16, &str)] = &[
    ("sporeGate", "192.168.4.1", 22, "SSH"),
    ("sporeGate", "192.168.4.1", 53, "dnsmasq DNS"),
    ("golgiBody", "10.13.37.1", 22, "SSH"),
    ("golgiBody", "10.13.37.1", 7700, "songBird federation"),
    ("golgiBody", "10.13.37.1", 2222, "Forgejo SSH"),
];

pub struct ServicePortProbe {
    meta: ProbeMeta,
}

impl Default for ServicePortProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl ServicePortProbe {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            meta: ProbeMeta {
                id: "service-port-probe",
                category: ProbeCategory::Network,
                description: "TCP connectivity to declared service ports",
                target: "all",
                supports_remediation: false,
            },
        }
    }

    async fn probe_impl(&self) -> ProbeResult {
        let start = Instant::now();
        let mut checks = Vec::new();

        for (gate, ip, port, service) in SERVICE_ENDPOINTS {
            let addr: SocketAddr = format!("{ip}:{port}").parse().expect("valid addr");
            let (reachable, latency) = tcp_probe(addr).await;

            checks.push(ProbeCheck {
                name: format!("{gate}:{port} ({service})"),
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
        let status = if any_fail {
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

impl Probe for ServicePortProbe {
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

async fn tcp_probe(addr: SocketAddr) -> (bool, Option<Duration>) {
    let start = Instant::now();
    let timeout = Duration::from_secs(5);

    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => (true, Some(start.elapsed())),
        _ => (false, None),
    }
}
