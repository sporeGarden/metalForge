// SPDX-License-Identifier: AGPL-3.0-or-later

pub mod handshake;
pub mod mesh_reachability;

use crate::registry::Probe;

pub fn register_probes(probes: &mut Vec<Box<dyn Probe>>) {
    probes.push(Box::new(handshake::WgHandshakeProbe::new()));
    probes.push(Box::new(mesh_reachability::WgMeshReachabilityProbe::new()));
}
