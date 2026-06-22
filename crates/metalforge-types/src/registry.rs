// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::probe::ProbeCategory;

/// Metadata entry for a registered probe.
#[derive(Debug, Clone)]
pub struct ProbeRegistryEntry {
    pub id: &'static str,
    pub category: ProbeCategory,
    pub description: &'static str,
    pub target: &'static str,
    pub supports_remediation: bool,
}
