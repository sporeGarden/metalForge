// SPDX-License-Identifier: AGPL-3.0-or-later

pub mod port_probe;
pub mod topology_sweep;

use metalforge_types::device::DeviceRegistry;

use crate::registry::Probe;

pub fn register_probes(probes: &mut Vec<Box<dyn Probe>>, registry: &DeviceRegistry) {
    probes.push(Box::new(topology_sweep::TopologySweepProbe::new(registry)));
    probes.push(Box::new(port_probe::ServicePortProbe::new()));
}
