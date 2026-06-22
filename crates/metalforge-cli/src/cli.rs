// SPDX-License-Identifier: AGPL-3.0-or-later

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "metalforge",
    about = "Hardware topology testing suite — springs as a spore on hardware",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Run hardware topology probes
    Probe {
        /// Probe category filter
        #[arg(long, short)]
        category: Option<CategoryArg>,

        /// Target gate name filter
        #[arg(long, short)]
        gate: Option<String>,

        /// Target device name filter
        #[arg(long, short)]
        device: Option<String>,

        /// Apply remediation for detected drift
        #[arg(long)]
        remediate: bool,

        /// Show what remediation would do without applying
        #[arg(long)]
        dry_run: bool,

        /// Output results as JSON
        #[arg(long)]
        json: bool,

        /// List registered probes without running them
        #[arg(long)]
        list: bool,
    },

    /// Dump merged hardware inventory from all sources
    Inventory,

    /// Quick status summary
    Status,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum CategoryArg {
    Wifi,
    Network,
    Wireguard,
    Dns,
    Dhcp,
    All,
}

impl CategoryArg {
    #[must_use]
    pub const fn to_probe_category(self) -> Option<metalforge_types::probe::ProbeCategory> {
        match self {
            Self::Wifi => Some(metalforge_types::probe::ProbeCategory::Wifi),
            Self::Network => Some(metalforge_types::probe::ProbeCategory::Network),
            Self::Wireguard => Some(metalforge_types::probe::ProbeCategory::Wireguard),
            Self::Dns => Some(metalforge_types::probe::ProbeCategory::Dns),
            Self::Dhcp => Some(metalforge_types::probe::ProbeCategory::Dhcp),
            Self::All => None,
        }
    }
}
