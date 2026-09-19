//! Runtime abstraction: how a pod is actually started/stopped. The only
//! implementation today is systemd-nspawn + machined (over zbus); the trait
//! keeps server.rs free of engine specifics so an OCI runtime (crun/youki)
//! can slot in later for systems without systemd.

pub mod nspawn;

use anyhow::Result;
use std::path::PathBuf;

pub use nspawn::SystemdNspawn;
use crate::state::LimitsSpec;
use rustypods_proto::BindSpec;

/// Everything an engine needs to boot one pod.
#[derive(Debug, Clone)]
pub struct StartSpec {
    pub name: String,
    pub rootfs: PathBuf,
    pub ephemeral: bool,
    pub private_users: bool,
    /// Read-only bind of the host agent binaries → /run/rustypods/bin.
    pub agent_bin: PathBuf,
    /// Per-pod channel dir → /run/rustypods/run.
    pub run_dir: PathBuf,
    /// Host SHM dir → /run/rustypods/shm.
    pub shm_dir: PathBuf,
    /// "hostPort:podPort" — engine decides the netns strategy.
    pub ports: Vec<String>,
    /// User-configured bind mounts (validated BindSpec).
    pub binds: Vec<BindSpec>,
    /// Stack members join this pre-made netns instead of getting a veth.
    pub netns: Option<PathBuf>,
    /// Console output is appended here.
    pub log: PathBuf,
    /// OCI payload (entrypoint+cmd). Some → non-boot mode: the image has no
    /// systemd, nspawn execs this argv directly. None → --boot.
    pub payload: Option<Vec<String>>,
    /// OCI env ("K=V") → nspawn --setenv.
    pub env: Vec<String>,
    /// OCI working dir → nspawn --chdir (non-boot only).
    pub chdir: String,
}

#[tonic::async_trait]
pub trait RuntimeEngine: Send + Sync {
    /// Engine name for `ping`/logs, e.g. "systemd-nspawn".
    fn name(&self) -> &'static str;
    /// One-time startup hook (nspawn: wake machined over the bus).
    async fn init(&self) -> Result<()> {
        Ok(())
    }
    /// Spawn + register the pod and apply `limits` to its live scope.
    /// Returns the leader pid (init inside the pod).
    async fn start(&self, spec: &StartSpec, limits: &LimitsSpec) -> Result<u32>;
    /// Clean shutdown (SIGRTMIN+3 → terminate fallback for nspawn).
    async fn stop(&self, pod: &str) -> Result<()>;
    /// Leader pid while running, None otherwise.
    async fn running_pid(&self, pod: &str) -> Option<u32>;
    /// Hot-apply resource limits to the live pod scope.
    async fn apply_limits(&self, pod: &str, limits: &LimitsSpec) -> Result<()>;
    /// Control-plane health (nspawn: machined answers ListMachines).
    async fn healthy(&self) -> bool;
}
