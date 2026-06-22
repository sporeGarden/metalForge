// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lightweight SSH command execution via the system `ssh` binary.
//! Relies on `~/.ssh/config` and agent-forwarded keys — no libssh dependency.

use std::process::Output;
use std::time::Duration;

use tokio::process::Command;

#[derive(Debug, Clone)]
pub struct SshTarget {
    pub host: String,
    pub user: String,
    pub port: u16,
    pub connect_timeout: Duration,
}

impl SshTarget {
    #[must_use]
    pub fn new(host: &str, user: &str) -> Self {
        Self {
            host: host.to_string(),
            user: user.to_string(),
            port: 22,
            connect_timeout: Duration::from_secs(10),
        }
    }

    /// Execute a command over SSH, returning raw output.
    ///
    /// # Errors
    /// Returns an error if `ssh` fails to spawn.
    pub async fn exec(&self, command: &str) -> std::io::Result<Output> {
        Command::new("ssh")
            .arg("-o")
            .arg("BatchMode=yes")
            .arg("-o")
            .arg("StrictHostKeyChecking=accept-new")
            .arg("-o")
            .arg(format!(
                "ConnectTimeout={}",
                self.connect_timeout.as_secs()
            ))
            .arg("-p")
            .arg(self.port.to_string())
            .arg(format!("{}@{}", self.user, self.host))
            .arg(command)
            .output()
            .await
    }

    /// Execute and return stdout as a string (lossy).
    ///
    /// # Errors
    /// Returns `SshError::Connection` if SSH fails to connect, or
    /// `SshError::RemoteCommand` if the remote exit code is nonzero.
    pub async fn exec_stdout(&self, command: &str) -> Result<String, SshError> {
        let output = self.exec(command).await.map_err(|e| SshError::Connection {
            host: self.host.clone(),
            source: e,
        })?;

        if !output.status.success() {
            return Err(SshError::RemoteCommand {
                host: self.host.clone(),
                command: command.to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                exit_code: output.status.code(),
            });
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Check if the target is reachable via SSH.
    pub async fn is_reachable(&self) -> bool {
        self.exec("true").await.is_ok_and(|o| o.status.success())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SshError {
    #[error("SSH connection to {host} failed: {source}")]
    Connection {
        host: String,
        source: std::io::Error,
    },
    #[error("remote command on {host} failed (exit {exit_code:?}): {stderr}")]
    RemoteCommand {
        host: String,
        command: String,
        stderr: String,
        exit_code: Option<i32>,
    },
}
