// SPDX-License-Identifier: AGPL-3.0-or-later

pub mod flint2;

use metalforge_types::device::DeviceRegistry;

use crate::registry::Probe;

pub fn register_probes(probes: &mut Vec<Box<dyn Probe>>, registry: &DeviceRegistry) {
    for (name, spec) in registry.wifi_devices() {
        if spec.firmware.as_deref() == Some("openwrt")
            && spec.model.contains("MT6000")
        {
            probes.push(Box::new(flint2::Flint2WifiProbe::new(
                name.to_string(),
                spec.clone(),
            )));
        }
    }
}
