// SPDX-License-Identifier: AGPL-3.0-or-later

//! Probe registry — primalSpring-style `build_registry()` pattern.
//! Each probe module registers its probes here.

use std::future::Future;
use std::pin::Pin;

use metalforge_types::device::DeviceRegistry;
use metalforge_types::probe::{ProbeCategory, ProbeMeta, ProbeResult};

use crate::dhcp;
use crate::dns;
use crate::network;
use crate::wifi;
use crate::wireguard;

/// Trait implemented by all hardware probes.
/// Uses boxed futures for object safety with dynamic dispatch.
pub trait Probe: Send + Sync {
    fn meta(&self) -> &ProbeMeta;
    fn run(&self, remediate: bool, dry_run: bool)
        -> Pin<Box<dyn Future<Output = ProbeResult> + Send + '_>>;
}

pub struct ProbeRegistry {
    probes: Vec<Box<dyn Probe>>,
}

/// Expected total probe count — bump when adding probes.
const EXPECTED_PROBE_COUNT: usize = 7;

impl ProbeRegistry {
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn build(device_registry: &DeviceRegistry) -> Self {
        let mut probes: Vec<Box<dyn Probe>> = Vec::new();

        wifi::register_probes(&mut probes, device_registry);
        network::register_probes(&mut probes, device_registry);
        wireguard::register_probes(&mut probes);
        dns::register_probes(&mut probes);
        dhcp::register_probes(&mut probes);

        assert_eq!(
            probes.len(),
            EXPECTED_PROBE_COUNT,
            "probe count mismatch: expected {EXPECTED_PROBE_COUNT}, got {}. \
             Update EXPECTED_PROBE_COUNT when adding/removing probes.",
            probes.len()
        );

        Self { probes }
    }

    #[must_use]
    pub fn filter(
        &self,
        category: Option<ProbeCategory>,
        gate: Option<&str>,
        device: Option<&str>,
    ) -> Vec<&dyn Probe> {
        self.probes
            .iter()
            .filter(|p| {
                let meta = p.meta();
                category.is_none_or(|c| c == meta.category)
                    && gate.is_none_or(|g| meta.target == g)
                    && device.is_none_or(|d| meta.target == d)
            })
            .map(Box::as_ref)
            .collect()
    }

    #[must_use]
    pub fn list(&self) -> Vec<&ProbeMeta> {
        self.probes.iter().map(|p| p.meta()).collect()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.probes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.probes.is_empty()
    }
}
