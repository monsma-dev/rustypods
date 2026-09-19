//! rustypods-agent — in-pod telemetry. Samples the pod's own cgroup v2
//! counters + PSI and pushes Metric messages to rustypodsd over the
//! bind-mounted UDS at /run/rustypods/run/agent.sock. Reconnects forever:
//! daemon restarts and pod boot races just retry.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use tokio::net::UnixStream;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Endpoint;
use tower::service_fn;

use rustypods_proto::rpc::agent_client::AgentClient;
use rustypods_proto::rpc::Metric;
use rustypods_proto::POD_AGENT_SOCK;

const INTERVAL: Duration = Duration::from_secs(2);

fn read_u64(path: &str) -> Option<u64> {
    let s = std::fs::read_to_string(path).ok()?;
    let s = s.trim();
    if s == "max" {
        return Some(0); // "max" → report 0 (unset)
    }
    s.parse().ok()
}

/// "some avg10=0.00 avg60=…" → avg10
fn psi_some(path: &str) -> f64 {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|t| {
            t.lines()
                .find(|l| l.starts_with("some"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|kv| kv.strip_prefix("avg10="))
                .and_then(|v| v.parse().ok())
        })
        .unwrap_or(0.0)
}

fn cgroup_val(file: &str) -> Option<u64> {
    read_u64(&format!("/sys/fs/cgroup/{file}"))
}

fn cpu_usage_usec() -> Option<u64> {
    let stat = std::fs::read_to_string("/sys/fs/cgroup/cpu.stat").ok()?;
    stat.lines()
        .find(|l| l.starts_with("usage_usec"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// cpu_pct = percentage of one core (can exceed 100 on multicore).
fn sample(prev: Option<(u64, u64)>) -> (Metric, (u64, u64)) {
    let usage = cpu_usage_usec().unwrap_or(0);
    let wall_us = (INTERVAL.as_micros() as u64).max(1);
    let cpu_pct = match prev {
        Some((p_usage, p_wall)) if usage >= p_usage => {
            let dt = wall_us.max(1) as f64;
            let _ = p_wall;
            (usage - p_usage) as f64 / dt * 100.0
        }
        _ => 0.0,
    };
    (
        Metric {
            ts_unix_ms: now_ms(),
            mem_bytes: cgroup_val("memory.current").unwrap_or(0),
            mem_high_bytes: cgroup_val("memory.high").unwrap_or(0),
            cpu_pct,
            pids: cgroup_val("pids.current").unwrap_or(0),
            mem_psi_avg10: psi_some("/proc/pressure/memory"),
            io_psi_avg10: psi_some("/proc/pressure/io"),
        },
        (usage, now_ms() * 1000),
    )
}

async fn run() -> Result<()> {
    let sock = std::path::PathBuf::from(POD_AGENT_SOCK);
    let ch = Endpoint::try_from("http://[::]:0")?
        .connect_with_connector(service_fn(move |_: http::Uri| {
            let p = sock.clone();
            async move { UnixStream::connect(p).await.map(hyper_util::rt::TokioIo::new) }
        }))
        .await?;
    let mut client = AgentClient::new(ch);
    let (tx, rx) = tokio::sync::mpsc::channel::<Metric>(8);
    let rpc = tokio::spawn(async move { client.stream_metrics(ReceiverStream::new(rx)).await });
    let mut prev = None;
    loop {
        let (m, cur) = sample(prev);
        prev = Some(cur);
        if tx.send(m).await.is_err() || rpc.is_finished() {
            break;
        }
        tokio::time::sleep(INTERVAL).await;
    }
    drop(tx);
    let _ = rpc.await;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    tracing::info!("rustypods-agent v{} → {}", env!("CARGO_PKG_VERSION"), POD_AGENT_SOCK);
    loop {
        if let Err(e) = run().await {
            tracing::warn!("daemon channel: {e:#}");
        }
        tokio::time::sleep(INTERVAL).await;
    }
}
