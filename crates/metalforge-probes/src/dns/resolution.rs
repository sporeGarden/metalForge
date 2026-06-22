// SPDX-License-Identifier: AGPL-3.0-or-later

//! DNS resolution probe: forward lookups, ad-blocking validation, `DoT` chain check.

use std::future::Future;
use std::pin::Pin;
use std::time::Instant;

use metalforge_types::probe::{ProbeCategory, ProbeCheck, ProbeMeta, ProbeResult, ProbeStatus};

use crate::registry::Probe;

/// Domains that should resolve successfully.
const VALID_DOMAINS: &[&str] = &["git.primals.eco", "google.com", "cloudflare.com"];

/// Ad/tracker domains that should be blocked (resolve to 0.0.0.0).
const BLOCKED_DOMAINS: &[&str] = &[
    "ads.google.com",
    "tracking.example.com",
    "pagead2.googlesyndication.com",
];

pub struct DnsResolutionProbe {
    meta: ProbeMeta,
}

impl Default for DnsResolutionProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsResolutionProbe {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            meta: ProbeMeta {
                id: "dns-resolution",
                category: ProbeCategory::Dns,
                description: "DNS forward resolution, ad-blocking, and DoT chain validation",
                target: "sporeGate",
                supports_remediation: false,
            },
        }
    }

    async fn probe_impl(&self) -> ProbeResult {
        let start = Instant::now();
        let mut checks = Vec::new();

        // Check that dnsmasq is running
        let dnsmasq_running = is_process_running("dnsmasq").await;
        checks.push(ProbeCheck {
            name: "dnsmasq process".to_string(),
            status: if dnsmasq_running {
                ProbeStatus::Pass
            } else {
                ProbeStatus::Fail
            },
            detail: None,
            latency: None,
        });

        // Check that stubby (DoT forwarder) is running
        let stubby_running = is_process_running("stubby").await;
        checks.push(ProbeCheck {
            name: "stubby DoT forwarder".to_string(),
            status: if stubby_running {
                ProbeStatus::Pass
            } else {
                ProbeStatus::Fail
            },
            detail: if stubby_running {
                Some("DNS-over-TLS chain active".to_string())
            } else {
                Some("stubby not running — DNS queries sent in cleartext".to_string())
            },
            latency: None,
        });

        // Forward resolution tests
        for domain in VALID_DOMAINS {
            let (resolved, detail) = resolve_domain(domain).await;
            checks.push(ProbeCheck {
                name: format!("resolve {domain}"),
                status: if resolved {
                    ProbeStatus::Pass
                } else {
                    ProbeStatus::Fail
                },
                detail: Some(detail),
                latency: None,
            });
        }

        // Ad-blocking tests
        for domain in BLOCKED_DOMAINS {
            let (blocked, detail) = check_blocked(domain).await;
            checks.push(ProbeCheck {
                name: format!("block {domain}"),
                status: if blocked {
                    ProbeStatus::Pass
                } else {
                    ProbeStatus::Drift
                },
                detail: Some(detail),
                latency: None,
            });
        }

        let any_fail = checks.iter().any(|c| c.status == ProbeStatus::Fail);
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

impl Probe for DnsResolutionProbe {
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

/// Resolve a domain using `getent hosts` (works without dig/nslookup).
async fn resolve_domain(domain: &str) -> (bool, String) {
    match tokio::process::Command::new("getent")
        .args(["hosts", domain])
        .output()
        .await
    {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let ip = stdout.split_whitespace().next().unwrap_or("?");
            (true, format!("resolved to {ip}"))
        }
        Ok(_) => (false, "NXDOMAIN or resolution failure".to_string()),
        Err(e) => (false, format!("getent failed: {e}")),
    }
}

/// Check if a domain is blocked (resolves to 0.0.0.0 or fails).
async fn check_blocked(domain: &str) -> (bool, String) {
    match tokio::process::Command::new("getent")
        .args(["hosts", domain])
        .output()
        .await
    {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let ip = stdout.split_whitespace().next().unwrap_or("");
            if ip == "0.0.0.0" || ip == "127.0.0.1" || ip == "::1" {
                (true, format!("blocked → {ip}"))
            } else {
                (false, format!("NOT blocked — resolved to {ip}"))
            }
        }
        Ok(_) => {
            // NXDOMAIN counts as blocked
            (true, "blocked (NXDOMAIN)".to_string())
        }
        Err(e) => (false, format!("getent failed: {e}")),
    }
}

async fn is_process_running(name: &str) -> bool {
    tokio::process::Command::new("pgrep")
        .arg("-x")
        .arg(name)
        .output()
        .await
        .is_ok_and(|o| o.status.success())
}
