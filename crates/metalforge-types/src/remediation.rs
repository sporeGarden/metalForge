// SPDX-License-Identifier: AGPL-3.0-or-later

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftField {
    pub field: String,
    pub expected: String,
    pub actual: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftReport {
    pub device: String,
    pub fields: Vec<DriftField>,
}

impl DriftReport {
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.fields.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationOutcome {
    Applied,
    DryRun,
    Failed,
    NotNeeded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationAction {
    pub device: String,
    pub description: String,
    pub commands: Vec<String>,
    pub outcome: RemediationOutcome,
    pub error: Option<String>,
}
