// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceType {
    WifiAp,
    Switch,
    Router,
    Gateway,
    Server,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadioConfig {
    pub dat_path: String,
    pub ssid: String,
    pub auth_mode: String,
    pub encryp_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSpec {
    #[serde(rename = "type")]
    pub device_type: DeviceType,
    pub model: String,
    #[serde(default)]
    pub firmware: Option<String>,
    pub ip: String,
    #[serde(default)]
    pub ssh_user: Option<String>,
    pub site: String,
    #[serde(default)]
    pub radios: BTreeMap<String, RadioConfig>,
    #[serde(default)]
    pub ports: Vec<String>,
    #[serde(default)]
    pub management_ip: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRegistry {
    pub devices: BTreeMap<String, DeviceSpec>,
}

impl DeviceRegistry {
    /// Load from a TOML file.
    ///
    /// # Errors
    /// Returns an error if the file can't be read or parsed.
    pub fn load(path: &std::path::Path) -> Result<Self, DeviceRegistryError> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| DeviceRegistryError::Io(path.display().to_string(), e))?;
        toml::from_str(&contents)
            .map_err(|e| DeviceRegistryError::Parse(path.display().to_string(), e))
    }

    #[must_use]
    pub fn wifi_devices(&self) -> Vec<(&str, &DeviceSpec)> {
        self.devices
            .iter()
            .filter(|(_, d)| d.device_type == DeviceType::WifiAp)
            .map(|(name, spec)| (name.as_str(), spec))
            .collect()
    }

    #[must_use]
    pub fn devices_at_site(&self, site: &str) -> Vec<(&str, &DeviceSpec)> {
        self.devices
            .iter()
            .filter(|(_, d)| d.site == site)
            .map(|(name, spec)| (name.as_str(), spec))
            .collect()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DeviceRegistryError {
    #[error("failed to read {0}: {1}")]
    Io(String, std::io::Error),
    #[error("failed to parse {0}: {1}")]
    Parse(String, toml::de::Error),
}
