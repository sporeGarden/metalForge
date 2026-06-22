// SPDX-License-Identifier: AGPL-3.0-or-later

pub mod lease_audit;

use crate::registry::Probe;

pub fn register_probes(probes: &mut Vec<Box<dyn Probe>>) {
    probes.push(Box::new(lease_audit::DhcpLeaseAuditProbe::new()));
}
