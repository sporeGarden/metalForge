// SPDX-License-Identifier: AGPL-3.0-or-later

mod cli;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use cli::{Cli, Command};
use metalforge_probes::executor::ProbeExecutor;
use metalforge_probes::registry::ProbeRegistry;
use metalforge_types::device::DeviceRegistry;

fn find_config_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("METALFORGE_CONFIG_DIR") {
        return PathBuf::from(dir);
    }

    let mut candidate = std::env::current_dir().unwrap_or_default();
    loop {
        let config = candidate.join("config").join("device_registry.toml");
        if config.exists() {
            return candidate.join("config");
        }
        if !candidate.pop() {
            break;
        }
    }

    PathBuf::from("config")
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("metalforge=info")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    let config_dir = find_config_dir();
    let registry_path = config_dir.join("device_registry.toml");

    let device_registry = match DeviceRegistry::load(&registry_path) {
        Ok(reg) => {
            tracing::info!(
                path = %registry_path.display(),
                devices = reg.devices.len(),
                "loaded device registry"
            );
            reg
        }
        Err(e) => {
            tracing::warn!("device registry not found at {}: {e}", registry_path.display());
            tracing::warn!("using empty registry — device-specific probes will be skipped");
            DeviceRegistry {
                devices: std::collections::BTreeMap::new(),
            }
        }
    };

    match cli.command {
        Command::Probe {
            category,
            gate,
            device,
            remediate,
            dry_run,
            json,
            list,
        } => {
            let probe_registry = ProbeRegistry::build(&device_registry);

            if list {
                eprintln!("registered probes ({}):", probe_registry.len());
                for meta in probe_registry.list() {
                    eprintln!(
                        "  [{:10}] {:<30} target={:<20} remediation={}",
                        meta.category.to_string(),
                        meta.id,
                        meta.target,
                        if meta.supports_remediation {
                            "yes"
                        } else {
                            "no"
                        }
                    );
                }
                return ExitCode::SUCCESS;
            }

            let category_filter = category.and_then(cli::CategoryArg::to_probe_category);
            let executor = ProbeExecutor::new(probe_registry, remediate, dry_run);
            let report = executor
                .run(category_filter, gate.as_deref(), device.as_deref())
                .await;

            if json {
                if let Ok(j) = serde_json::to_string_pretty(&report.results) {
                    println!("{j}");
                }
            } else {
                report.print_summary();
            }

            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            ExitCode::from(report.exit_code() as u8)
        }

        Command::Inventory => {
            eprintln!("--- metalForge hardware inventory ---");
            eprintln!("\ndevices ({}):", device_registry.devices.len());
            for (name, spec) in &device_registry.devices {
                eprintln!(
                    "  {name}: {:?} {} @ {} (site: {})",
                    spec.device_type, spec.model, spec.ip, spec.site
                );
                for (band, radio) in &spec.radios {
                    eprintln!("    radio {band}: SSID={} auth={}", radio.ssid, radio.auth_mode);
                }
            }
            ExitCode::SUCCESS
        }

        Command::Status => {
            let probe_registry = ProbeRegistry::build(&device_registry);
            let executor = ProbeExecutor::new(probe_registry, false, false);
            let report = executor.run(None, None, None).await;
            report.print_summary();
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            ExitCode::from(report.exit_code() as u8)
        }
    }
}
