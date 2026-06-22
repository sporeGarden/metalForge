// SPDX-License-Identifier: AGPL-3.0-or-later

pub mod dot_chain;
pub mod resolution;

use crate::registry::Probe;

pub fn register_probes(probes: &mut Vec<Box<dyn Probe>>) {
    probes.push(Box::new(resolution::DnsResolutionProbe::new()));
}
