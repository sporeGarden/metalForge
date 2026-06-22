// SPDX-License-Identifier: AGPL-3.0-or-later

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeCategory {
    Wifi,
    Network,
    Wireguard,
    Dns,
    Dhcp,
}

impl fmt::Display for ProbeCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wifi => write!(f, "wifi"),
            Self::Network => write!(f, "network"),
            Self::Wireguard => write!(f, "wireguard"),
            Self::Dns => write!(f, "dns"),
            Self::Dhcp => write!(f, "dhcp"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProbeMeta {
    pub id: &'static str,
    pub category: ProbeCategory,
    pub description: &'static str,
    pub target: &'static str,
    pub supports_remediation: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    Pass,
    Fail,
    Drift,
    Remediated,
    Skipped,
    Unreachable,
}

impl ProbeStatus {
    #[must_use]
    pub const fn is_healthy(self) -> bool {
        matches!(self, Self::Pass | Self::Remediated)
    }

    #[must_use]
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::Pass | Self::Remediated => 0,
            Self::Skipped => 2,
            _ => 1,
        }
    }
}

impl fmt::Display for ProbeStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Fail => write!(f, "FAIL"),
            Self::Drift => write!(f, "DRIFT"),
            Self::Remediated => write!(f, "REMEDIATED"),
            Self::Skipped => write!(f, "SKIP"),
            Self::Unreachable => write!(f, "UNREACHABLE"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProbeCheck {
    pub name: String,
    pub status: ProbeStatus,
    pub detail: Option<String>,
    #[serde(
        serialize_with = "serialize_duration_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub latency: Option<Duration>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProbeResult {
    pub meta: ProbeMeta,
    pub status: ProbeStatus,
    pub checks: Vec<ProbeCheck>,
    pub timestamp: String,
    #[serde(serialize_with = "serialize_duration")]
    pub elapsed: Duration,
    pub remediation_applied: bool,
}

impl ProbeResult {
    #[must_use]
    pub fn summary_line(&self) -> String {
        let checks_pass = self.checks.iter().filter(|c| c.status.is_healthy()).count();
        format!(
            "[{}] {} — {} ({}/{} checks)",
            self.meta.category,
            self.meta.id,
            self.status,
            checks_pass,
            self.checks.len()
        )
    }

    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        self.status.exit_code()
    }
}

#[allow(clippy::cast_possible_truncation)]
fn serialize_duration<S: serde::Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_u64(d.as_millis() as u64)
}

#[allow(clippy::ref_option, clippy::cast_possible_truncation)]
fn serialize_duration_opt<S: serde::Serializer>(
    d: &Option<Duration>,
    s: S,
) -> Result<S::Ok, S::Error> {
    match d {
        Some(d) => s.serialize_some(&(d.as_millis() as u64)),
        None => s.serialize_none(),
    }
}
