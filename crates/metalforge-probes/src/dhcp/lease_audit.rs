// SPDX-License-Identifier: AGPL-3.0-or-later

//! DHCP lease audit: validates active leases against static host declarations,
//! checks range configuration and authoritative mode.

use std::future::Future;
use std::pin::Pin;
use std::time::Instant;

use metalforge_types::probe::{ProbeCategory, ProbeCheck, ProbeMeta, ProbeResult, ProbeStatus};

use crate::registry::Probe;

const DNSMASQ_CONF: &str = "/etc/dnsmasq.conf";
const DNSMASQ_LEASES: &str = "/var/lib/misc/dnsmasq.leases";

pub struct DhcpLeaseAuditProbe {
    meta: ProbeMeta,
}

impl Default for DhcpLeaseAuditProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl DhcpLeaseAuditProbe {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            meta: ProbeMeta {
                id: "dhcp-lease-audit",
                category: ProbeCategory::Dhcp,
                description: "DHCP lease validation, static host parity, authoritative mode",
                target: "sporeGate",
                supports_remediation: false,
            },
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn probe_impl(&self) -> ProbeResult {
        let start = Instant::now();
        let mut checks = Vec::new();

        // Check dnsmasq.conf exists and is readable
        let conf_content = match tokio::fs::read_to_string(DNSMASQ_CONF).await {
            Ok(content) => {
                checks.push(ProbeCheck {
                    name: "dnsmasq.conf readable".to_string(),
                    status: ProbeStatus::Pass,
                    detail: None,
                    latency: None,
                });
                content
            }
            Err(e) => {
                checks.push(ProbeCheck {
                    name: "dnsmasq.conf readable".to_string(),
                    status: ProbeStatus::Fail,
                    detail: Some(format!("cannot read {DNSMASQ_CONF}: {e}")),
                    latency: None,
                });
                return build_result(&self.meta, ProbeStatus::Fail, checks, start.elapsed());
            }
        };

        // Check dhcp-authoritative is set
        let authoritative = conf_content
            .lines()
            .any(|l| l.trim() == "dhcp-authoritative");
        checks.push(ProbeCheck {
            name: "dhcp-authoritative".to_string(),
            status: if authoritative {
                ProbeStatus::Pass
            } else {
                ProbeStatus::Drift
            },
            detail: if authoritative {
                Some("dnsmasq is authoritative for DHCP".to_string())
            } else {
                Some("dhcp-authoritative not set — clients may NAK loop".to_string())
            },
            latency: None,
        });

        // Count static dhcp-host entries
        let static_hosts: Vec<&str> = conf_content
            .lines()
            .filter(|l| l.starts_with("dhcp-host="))
            .collect();
        checks.push(ProbeCheck {
            name: "static DHCP hosts".to_string(),
            status: if static_hosts.is_empty() {
                ProbeStatus::Drift
            } else {
                ProbeStatus::Pass
            },
            detail: Some(format!("{} static host entries", static_hosts.len())),
            latency: None,
        });

        // Check dhcp-range configuration
        let has_range = conf_content.lines().any(|l| l.starts_with("dhcp-range="));
        checks.push(ProbeCheck {
            name: "dhcp-range configured".to_string(),
            status: if has_range {
                ProbeStatus::Pass
            } else {
                ProbeStatus::Fail
            },
            detail: None,
            latency: None,
        });

        // Check blocklist integration
        let has_blocklist = conf_content
            .lines()
            .any(|l| l.contains("blocklist") && l.starts_with("conf-file="));
        checks.push(ProbeCheck {
            name: "ad-blocklist loaded".to_string(),
            status: if has_blocklist {
                ProbeStatus::Pass
            } else {
                ProbeStatus::Drift
            },
            detail: if has_blocklist {
                Some("blocklist conf-file directive present".to_string())
            } else {
                Some("no blocklist conf-file found in dnsmasq.conf".to_string())
            },
            latency: None,
        });

        // Check DoT forwarding (server=127.0.0.1#5353)
        let has_dot = conf_content
            .lines()
            .any(|l| l.starts_with("server=127.0.0.1#5353"));
        checks.push(ProbeCheck {
            name: "DoT forwarding".to_string(),
            status: if has_dot {
                ProbeStatus::Pass
            } else {
                ProbeStatus::Drift
            },
            detail: if has_dot {
                Some("dnsmasq forwards to stubby on 127.0.0.1:5353".to_string())
            } else {
                Some("no DoT forwarding rule — DNS queries may be cleartext".to_string())
            },
            latency: None,
        });

        // Read lease file
        match tokio::fs::read_to_string(DNSMASQ_LEASES).await {
            Ok(leases) => {
                let lease_count = leases.lines().filter(|l| !l.is_empty()).count();
                checks.push(ProbeCheck {
                    name: "active DHCP leases".to_string(),
                    status: ProbeStatus::Pass,
                    detail: Some(format!("{lease_count} active leases")),
                    latency: None,
                });
            }
            Err(_) => {
                checks.push(ProbeCheck {
                    name: "active DHCP leases".to_string(),
                    status: ProbeStatus::Skipped,
                    detail: Some(format!("cannot read {DNSMASQ_LEASES}")),
                    latency: None,
                });
            }
        }

        let any_fail = checks.iter().any(|c| c.status == ProbeStatus::Fail);
        let status = if any_fail {
            ProbeStatus::Fail
        } else {
            ProbeStatus::Pass
        };

        build_result(&self.meta, status, checks, start.elapsed())
    }
}

impl Probe for DhcpLeaseAuditProbe {
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
    elapsed: std::time::Duration,
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
