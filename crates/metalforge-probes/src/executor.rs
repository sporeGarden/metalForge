// SPDX-License-Identifier: AGPL-3.0-or-later

//! Probe executor: runs probes, collects results, computes aggregate status.

use std::time::Instant;

use metalforge_types::probe::{ProbeCategory, ProbeResult, ProbeStatus};

use crate::registry::ProbeRegistry;

pub struct ProbeExecutor {
    registry: ProbeRegistry,
    remediate: bool,
    dry_run: bool,
}

pub struct ExecutionReport {
    pub results: Vec<ProbeResult>,
    pub pass: usize,
    pub fail: usize,
    pub drift: usize,
    pub skip: usize,
    pub unreachable: usize,
}

impl ExecutionReport {
    #[must_use]
    pub fn aggregate_status(&self) -> ProbeStatus {
        if self.fail > 0 || self.drift > 0 || self.unreachable > 0 {
            ProbeStatus::Fail
        } else if self.skip == self.results.len() {
            ProbeStatus::Skipped
        } else {
            ProbeStatus::Pass
        }
    }

    #[must_use]
    pub fn exit_code(&self) -> i32 {
        self.aggregate_status().exit_code()
    }

    pub fn print_summary(&self) {
        eprintln!("\n--- metalForge probe summary ---");
        for r in &self.results {
            eprintln!("  {}", r.summary_line());
        }
        eprintln!(
            "\n  total: {} | pass: {} | fail: {} | drift: {} | skip: {} | unreachable: {}",
            self.results.len(),
            self.pass,
            self.fail,
            self.drift,
            self.skip,
            self.unreachable
        );
    }
}

impl ProbeExecutor {
    #[must_use]
    pub const fn new(registry: ProbeRegistry, remediate: bool, dry_run: bool) -> Self {
        Self {
            registry,
            remediate,
            dry_run,
        }
    }

    pub async fn run(
        &self,
        category_filter: Option<ProbeCategory>,
        gate_filter: Option<&str>,
        device_filter: Option<&str>,
    ) -> ExecutionReport {
        let start = Instant::now();
        let probes = self
            .registry
            .filter(category_filter, gate_filter, device_filter);

        let mut results = Vec::new();

        for probe in &probes {
            tracing::info!(
                probe = probe.meta().id,
                category = %probe.meta().category,
                "running probe"
            );

            let probe_start = Instant::now();
            let result = probe.run(self.remediate, self.dry_run).await;
            let _elapsed = probe_start.elapsed();

            tracing::info!(
                probe = result.meta.id,
                status = %result.status,
                checks = result.checks.len(),
                "probe complete"
            );

            results.push(result);
        }

        let pass = results
            .iter()
            .filter(|r| r.status == ProbeStatus::Pass || r.status == ProbeStatus::Remediated)
            .count();
        let fail = results
            .iter()
            .filter(|r| r.status == ProbeStatus::Fail)
            .count();
        let drift = results
            .iter()
            .filter(|r| r.status == ProbeStatus::Drift)
            .count();
        let skip = results
            .iter()
            .filter(|r| r.status == ProbeStatus::Skipped)
            .count();
        let unreachable = results
            .iter()
            .filter(|r| r.status == ProbeStatus::Unreachable)
            .count();

        let _total_elapsed = start.elapsed();

        ExecutionReport {
            results,
            pass,
            fail,
            drift,
            skip,
            unreachable,
        }
    }
}
