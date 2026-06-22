// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::device::DeviceSpec;

/// Merged hardware inventory from `device_registry.toml` + `TOPOLOGY_MAP` + manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareInventory {
    pub devices: BTreeMap<String, DeviceSpec>,
    pub gates: BTreeMap<String, GateHardware>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateHardware {
    pub name: String,
    pub zone: Option<String>,
    pub site: Option<String>,
    pub hub_port: Option<String>,
    pub link_speed_mbps: Option<u32>,
    pub wg_ip: Option<String>,
    pub arch: Option<String>,
    pub gpu_target: Option<String>,
    pub lan_ip: Option<String>,
    pub notes: Option<String>,
}
