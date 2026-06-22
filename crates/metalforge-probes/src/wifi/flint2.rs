// SPDX-License-Identifier: AGPL-3.0-or-later

//! Flint 2 (GL-MT6000) `WiFi` configuration drift detection and remediation.
//!
//! The `MediaTek` driver reads radio config from `.dat` files, and firmware
//! updates / reboots can overwrite SSID, `AuthMode`, and `EncrypType` fields.
//! This probe validates the `.dat` files match the declared device registry
//! and optionally remediates by writing correct values + `wifi reload`.

use std::future::Future;
use std::pin::Pin;
use std::time::Instant;

use metalforge_types::device::DeviceSpec;
use metalforge_types::probe::{ProbeCategory, ProbeCheck, ProbeMeta, ProbeResult, ProbeStatus};
use metalforge_types::remediation::{DriftField, DriftReport, RemediationAction, RemediationOutcome};

use crate::registry::Probe;
use crate::ssh::SshTarget;

pub struct Flint2WifiProbe {
    device_name: String,
    spec: DeviceSpec,
    meta: ProbeMeta,
}

impl Flint2WifiProbe {
    #[must_use]
    pub const fn new(device_name: String, spec: DeviceSpec) -> Self {
        let meta = ProbeMeta {
            id: "flint2-wifi-drift",
            category: ProbeCategory::Wifi,
            description: "Validate Flint 2 MediaTek WiFi .dat files match declared config",
            target: "flint2_house2",
            supports_remediation: true,
        };
        Self {
            device_name,
            spec,
            meta,
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn probe_impl(&self, remediate: bool, dry_run: bool) -> ProbeResult {
        let start = Instant::now();
        let mut checks = Vec::new();
        let mut drift_reports = Vec::new();
        let mut remediations = Vec::new();

        let ssh_user = self.spec.ssh_user.as_deref().unwrap_or("root");
        let ssh = SshTarget::new(&self.spec.ip, ssh_user);

        let reachable = ssh.is_reachable().await;
        checks.push(ProbeCheck {
            name: format!("{} SSH reachable", self.spec.ip),
            status: if reachable {
                ProbeStatus::Pass
            } else {
                ProbeStatus::Unreachable
            },
            detail: None,
            latency: None,
        });

        if !reachable {
            return self.build_result(ProbeStatus::Unreachable, checks, false, start.elapsed());
        }

        let psk_env = std::env::var("METALFORGE_WIFI_PSK").ok();

        for (band_name, radio) in &self.spec.radios {
            let dat_content = match ssh.exec_stdout(&format!("cat {}", radio.dat_path)).await {
                Ok(content) => content,
                Err(e) => {
                    checks.push(ProbeCheck {
                        name: format!("{band_name} .dat readable"),
                        status: ProbeStatus::Fail,
                        detail: Some(format!("failed to read {}: {e}", radio.dat_path)),
                        latency: None,
                    });
                    continue;
                }
            };

            checks.push(ProbeCheck {
                name: format!("{band_name} .dat readable"),
                status: ProbeStatus::Pass,
                detail: None,
                latency: None,
            });

            let mut drift = DriftReport {
                device: format!("{}:{}", self.device_name, band_name),
                fields: Vec::new(),
            };

            check_dat_field(&dat_content, "SSID1", &radio.ssid, &mut drift);
            check_dat_field(&dat_content, "AuthMode", &radio.auth_mode, &mut drift);
            check_dat_field(&dat_content, "EncrypType", &radio.encryp_type, &mut drift);

            if let Some(ref psk) = psk_env {
                check_dat_field(&dat_content, "WPAPSK1", psk, &mut drift);
            }

            if drift.is_clean() {
                checks.push(ProbeCheck {
                    name: format!("{band_name} config"),
                    status: ProbeStatus::Pass,
                    detail: Some("all fields match declared values".to_string()),
                    latency: None,
                });
            } else {
                let field_names: Vec<_> = drift.fields.iter().map(|f| f.field.clone()).collect();
                checks.push(ProbeCheck {
                    name: format!("{band_name} config"),
                    status: ProbeStatus::Drift,
                    detail: Some(format!("drift in: {}", field_names.join(", "))),
                    latency: None,
                });
                drift_reports.push(drift);
            }
        }

        // Verify iwinfo shows correct SSIDs
        if let Ok(iwinfo) = ssh.exec_stdout("iwinfo 2>/dev/null || true").await {
            let expected_ssid = self
                .spec
                .radios
                .values()
                .next()
                .map_or("", |r| r.ssid.as_str());

            let ssid_broadcast = iwinfo.contains(&format!("ESSID: \"{expected_ssid}\""));
            checks.push(ProbeCheck {
                name: "iwinfo SSID broadcast".to_string(),
                status: if ssid_broadcast {
                    ProbeStatus::Pass
                } else {
                    ProbeStatus::Drift
                },
                detail: if ssid_broadcast {
                    Some(format!("broadcasting \"{expected_ssid}\""))
                } else {
                    Some(format!(
                        "expected \"{expected_ssid}\" not found in iwinfo output"
                    ))
                },
                latency: None,
            });
        }

        let has_drift = !drift_reports.is_empty();
        let remediated = if has_drift && remediate {
            self.apply_remediation(&ssh, &drift_reports, &mut remediations, dry_run)
                .await
        } else {
            false
        };

        let status = if !has_drift {
            ProbeStatus::Pass
        } else if remediated {
            ProbeStatus::Remediated
        } else {
            ProbeStatus::Drift
        };

        self.build_result(status, checks, remediated, start.elapsed())
    }

    async fn apply_remediation(
        &self,
        ssh: &SshTarget,
        _drift_reports: &[DriftReport],
        remediations: &mut Vec<RemediationAction>,
        dry_run: bool,
    ) -> bool {
        let psk_env = std::env::var("METALFORGE_WIFI_PSK").ok();
        let mut all_ok = true;

        for radio in self.spec.radios.values() {
            let mut sed_commands = Vec::new();

            sed_commands.push(format!(
                "sed -i 's/^SSID1=.*/SSID1={}/' {}",
                radio.ssid, radio.dat_path
            ));
            sed_commands.push(format!(
                "sed -i 's/^AuthMode=.*/AuthMode={}/' {}",
                radio.auth_mode, radio.dat_path
            ));
            sed_commands.push(format!(
                "sed -i 's/^EncrypType=.*/EncrypType={}/' {}",
                radio.encryp_type, radio.dat_path
            ));

            if let Some(ref psk) = psk_env {
                sed_commands.push(format!(
                    "sed -i 's/^WPAPSK1=.*/WPAPSK1={psk}/' {}",
                    radio.dat_path
                ));
            }

            let full_command = sed_commands.join(" && ");

            let action = if dry_run {
                RemediationAction {
                    device: self.device_name.clone(),
                    description: format!("fix .dat fields in {}", radio.dat_path),
                    commands: sed_commands,
                    outcome: RemediationOutcome::DryRun,
                    error: None,
                }
            } else {
                match ssh.exec_stdout(&full_command).await {
                    Ok(_) => RemediationAction {
                        device: self.device_name.clone(),
                        description: format!("fixed .dat fields in {}", radio.dat_path),
                        commands: vec![full_command],
                        outcome: RemediationOutcome::Applied,
                        error: None,
                    },
                    Err(e) => {
                        all_ok = false;
                        RemediationAction {
                            device: self.device_name.clone(),
                            description: format!("failed to fix {}", radio.dat_path),
                            commands: vec![full_command],
                            outcome: RemediationOutcome::Failed,
                            error: Some(e.to_string()),
                        }
                    }
                }
            };

            remediations.push(action);
        }

        if all_ok && !dry_run {
            if let Err(e) = ssh.exec_stdout("wifi reload").await {
                tracing::warn!("wifi reload failed after remediation: {e}");
                all_ok = false;
            }
        }

        all_ok
    }

    fn build_result(
        &self,
        status: ProbeStatus,
        checks: Vec<ProbeCheck>,
        remediated: bool,
        elapsed: std::time::Duration,
    ) -> ProbeResult {
        ProbeResult {
            meta: self.meta.clone(),
            status,
            checks,
            timestamp: chrono::Utc::now().to_rfc3339(),
            elapsed,
            remediation_applied: remediated,
        }
    }
}

impl Probe for Flint2WifiProbe {
    fn meta(&self) -> &ProbeMeta {
        &self.meta
    }

    fn run(
        &self,
        remediate: bool,
        dry_run: bool,
    ) -> Pin<Box<dyn Future<Output = ProbeResult> + Send + '_>> {
        Box::pin(self.probe_impl(remediate, dry_run))
    }
}

fn parse_dat_field<'a>(content: &'a str, key: &str) -> Option<&'a str> {
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix(key) {
            if let Some(value) = rest.strip_prefix('=') {
                return Some(value.trim());
            }
        }
    }
    None
}

fn check_dat_field(content: &str, key: &str, expected: &str, drift: &mut DriftReport) {
    let actual = parse_dat_field(content, key).unwrap_or("");
    if actual != expected {
        drift.fields.push(DriftField {
            field: key.to_string(),
            expected: expected.to_string(),
            actual: actual.to_string(),
        });
    }
}
