//! Exec: enter a running pod via nsenter on the machined leader pid.
//! tty=true allocates a real host pty (setsid+TIOCSCTTY in the child) so job
//! control and Ctrl-C behave; tty=false uses plain pipes. The exec'd process
//! is moved into the pod's machined scope so MemoryHigh/CPUQuota still apply.

use anyhow::{Context, Result};
use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use rustypods_proto::rpc::{exec_chunk::Kind, ExecChunk, ExecExit, ExecStart};
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tonic::Streaming;

type Tx = mpsc::Sender<Result<ExecChunk, tonic::Status>>;

fn chunk_stdout(b: Vec<u8>) -> Result<ExecChunk, tonic::Status> {
    Ok(ExecChunk {
        kind: Some(Kind::Stdout(b)),
    })
}
fn chunk_stderr(b: Vec<u8>) -> Result<ExecChunk, tonic::Status> {
    Ok(ExecChunk {
        kind: Some(Kind::Stderr(b)),
    })
}
fn chunk_exit(code: i32) -> Result<ExecChunk, tonic::Status> {
    Ok(ExecChunk {
        kind: Some(Kind::Exit(ExecExit { code })),
    })
}

/// name → (uid, gid, home, shell), parsed from the image's own /etc/passwd.
pub fn passwd_entry(rootfs: &Path, user: &str) -> Option<(u32, u32, String, String)> {
    let text = std::fs::read_to_string(rootfs.join("etc/passwd")).ok()?;
    for line in text.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() >= 7 && f[0] == user {
            return Some((
                f[2].parse().ok()?,
                f[3].parse().ok()?,
                f[5].to_string(),
                f[6].to_string(),
            ));
        }
    }
    None
}

/// nsenter argv — pure, testable.
pub fn exec_argv(leader: u32, rootfs: &Path, start: &ExecStart) -> Result<Vec<OsString>> {
    let (uid, gid, home, shell) = if start.user.is_empty() || start.user == "root" {
        (0u32, 0u32, "/root".to_string(), "/bin/sh".to_string())
    } else {
        passwd_entry(rootfs, &start.user)
            .with_context(|| format!("user '{}' not in image passwd", start.user))?
    };
    let mut a: Vec<OsString> = vec![
        "nsenter".into(),
        "--target".into(),
        leader.to_string().into(),
        "--mount".into(),
        "--uts".into(),
        "--ipc".into(),
        "--net".into(),
        "--pid".into(),
        "--".into(),
    ];
    if uid != 0 {
        a.extend([
            "setpriv".into(),
            format!("--reuid={uid}").into(),
            format!("--regid={gid}").into(),
            "--init-groups".into(),
            "--".into(),
        ]);
    }
    a.push("env".into());
    a.push(format!("HOME={home}").into());
    a.push(format!("USER={}", if start.user.is_empty() { "root" } else { &start.user }).into());
    a.push(format!("LOGNAME={}", if start.user.is_empty() { "root" } else { &start.user }).into());
    for kv in &start.env {
        a.push(kv.clone().into());
    }
    if start.argv.is_empty() {
        // cd $HOME first (machinectl behavior), then exec login shell.
        a.push("/bin/sh".into());
        a.push("-c".into());
        a.push("cd \"$HOME\" && exec \"$0\" \"$@\"".into());
        a.push(shell.into());
        a.push("-l".into());
    } else {
        a.extend(start.argv.iter().map(OsString::from));
    }
    Ok(a)
}

/// nsenter forks with -p: the spawned pid is the waiter, its child is the
/// real payload in the pod pidns. Poll until the child shows up.
async fn nsenter_child_pid(parent: u32) -> Option<u32> {
    let f = format!("/proc/{parent}/task/{parent}/children");
    for _ in 0..60 {
        if let Ok(s) = std::fs::read_to_string(&f) {
            if let Some(p) = s.split_whitespace().next() {
                return p.parse().ok();
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    None
}

/// Move the payload into the pod scope as soon as it forks (decoupled from
/// the io bridge). Fallback chain below handles the no-internal-process rule.
fn spawn_cgroup_join(pod: String, nsenter_pid: u32) {
    tokio::spawn(async move {
        if let Some(child) = nsenter_child_pid(nsenter_pid).await {
            join_pod_cgroup(&pod, child);
        }
    });
}

fn join_pod_cgroup(pod: &str, pid: u32) {
    let base = format!("/sys/fs/cgroup/machine.slice/machine-{pod}.scope");
    tracing::info!("exec: pid {pid} → {base}");
    for procs in [
        format!("{base}/cgroup.procs"),
        format!("{base}/payload/cgroup.procs"),
    ] {
        match std::fs::write(&procs, pid.to_string()) {
            Ok(()) => {
                tracing::info!("exec: {pid} via {procs}");
                return;
            }
            Err(e) => tracing::info!("exec: {procs}: {e}"),
        }
    }
    // Delegated parents refuse procs (no-internal-process); own leaf works.
    let leaf = format!("{base}/rustypods-exec");
    match std::fs::create_dir_all(&leaf)
        .and_then(|_| std::fs::write(format!("{leaf}/cgroup.procs"), pid.to_string()))
    {
        Ok(()) => tracing::info!("exec: {pid} via {leaf}"),
        Err(e) => tracing::warn!("exec {pid} not moved into pod cgroup: {e}"),
    }
}

fn set_winsize(fd: std::os::fd::RawFd, rows: u32, cols: u32) {
    if rows == 0 || cols == 0 {
        return;
    }
    let ws = libc::winsize {
        ws_row: rows as u16,
        ws_col: cols as u16,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    unsafe {
        libc::ioctl(fd, libc::TIOCSWINSZ, &ws);
    }
}

/// openpty(3) via libc: master+slave as OwnedFd, optional initial winsize.
fn openpty(rows: u16, cols: u16) -> Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd)> {
    use std::os::fd::FromRawFd;
    unsafe {
        let m = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
        if m < 0 {
            return Err(std::io::Error::last_os_error()).context("posix_openpt");
        }
        if libc::grantpt(m) != 0 || libc::unlockpt(m) != 0 {
            return Err(std::io::Error::last_os_error()).context("grantpt/unlockpt");
        }
        if rows > 0 && cols > 0 {
            set_winsize(m, rows as u32, cols as u32);
        }
        let name = libc::ptsname(m);
        if name.is_null() {
            return Err(std::io::Error::last_os_error()).context("ptsname");
        }
        let s = libc::open(name, libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
        if s < 0 {
            return Err(std::io::Error::last_os_error()).context("open pts slave");
        }
        Ok((
            std::os::fd::OwnedFd::from_raw_fd(m),
            std::os::fd::OwnedFd::from_raw_fd(s),
        ))
    }
}

/// Wire up an exec session. `inbound` is the client stream positioned *after*
/// the ExecStart frame. All output (stdout/stderr + a terminal Exit chunk)
/// flows through `tx`.
pub async fn run(
    start: ExecStart,
    rootfs: &Path,
    leader: u32,
    inbound: Streaming<ExecChunk>,
    tx: Tx,
) -> Result<()> {
    let argv = exec_argv(leader, rootfs, &start)?;
    if start.tty {
        run_tty(&argv, &start, inbound, tx).await
    } else {
        run_pipe(&argv, start.pod.clone(), inbound, tx).await
    }
}

async fn run_tty(
    argv: &[OsString],
    start: &ExecStart,
    mut inbound: Streaming<ExecChunk>,
    tx: Tx,
) -> Result<()> {
    let (master, slave) = openpty(start.rows as u16, start.cols as u16)?;
    let slave_in = slave.try_clone().context("slave clone")?;
    let slave_err = slave.try_clone().context("slave clone")?;

    let mut scmd = std::process::Command::new(&argv[0]);
    scmd
        .args(&argv[1..])
        .stdin(Stdio::from(slave))
        .stdout(Stdio::from(slave_in))
        .stderr(Stdio::from(slave_err));
    unsafe {
        scmd.pre_exec(|| {
            libc::setsid();
            libc::ioctl(0, libc::TIOCSCTTY, 0);
            Ok(())
        });
    }
    let mut cmd = tokio::process::Command::from(scmd);
    cmd.kill_on_drop(true);
    let mut child = cmd.spawn().context("nsenter spawn")?;
    if let Some(pid) = child.id() {
        spawn_cgroup_join(start.pod.clone(), pid);
    }

    let master_file = std::fs::File::from(master);
    let reader_file = master_file.try_clone()?;

    // Reader: blocking pty reads → stdout chunks; signals drain via oneshot.
    let (drained_tx, drained_rx) = tokio::sync::oneshot::channel::<()>();
    let tx_r = tx.clone();
    std::thread::spawn(move || {
        let mut f = reader_file;
        let mut buf = [0u8; 8192];
        loop {
            match f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if tx_r.blocking_send(chunk_stdout(buf[..n].to_vec())).is_err() {
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                // EIO = slave side gone (child exited) — normal teardown.
                Err(_) => break,
            }
        }
        let _ = drained_tx.send(());
    });

    // Inbound: stdin bytes → master; winsize → TIOCSWINSZ (kernel raises
    // SIGWINCH on the fg process group). master_file is owned here — stdin
    // writes and winsize ioctls share the fd. Stream end = client gone:
    // for a tty that's a disconnect (Ctrl-D is data, not EOF) → kill child,
    // else the remote shell lingers as a zombie on the open pty.
    let (gone_tx, gone_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        use std::os::unix::io::AsRawFd;
        let mut f = master_file;
        while let Some(Ok(c)) = inbound.next().await {
            match c.kind {
                Some(Kind::Stdin(b)) => {
                    if f.write_all(&b).is_err() {
                        break;
                    }
                }
                Some(Kind::Winsize(w)) => set_winsize(f.as_raw_fd(), w.rows, w.cols),
                _ => {}
            }
        }
        let _ = gone_tx.send(());
    });

    // Waiter: child exit OF client-disconnect → reader drained → exit chunk
    // LAST (ordering).
    tokio::spawn(async move {
        let code = tokio::select! {
            st = child.wait() => st.map(|s| s.code().unwrap_or(1)).unwrap_or(1),
            _ = gone_rx => {
                let _ = child.kill().await;
                child.wait().await.map(|s| s.code().unwrap_or(1)).unwrap_or(1)
            }
        };
        let _ = drained_rx.await;
        let _ = tx.send(chunk_exit(code)).await;
    });
    Ok(())
}

async fn run_pipe(
    argv: &[OsString],
    pod: String,
    mut inbound: Streaming<ExecChunk>,
    tx: Tx,
) -> Result<()> {
    let mut scmd = std::process::Command::new(&argv[0]);
    scmd
        .args(&argv[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut cmd = tokio::process::Command::from(scmd);
    cmd.kill_on_drop(true);
    let mut child = cmd.spawn().context("nsenter spawn")?;
    if let Some(pid) = child.id() {
        spawn_cgroup_join(pod, pid);
    }
    let mut stdin = child.stdin.take().context("stdin")?;
    let mut stdout = child.stdout.take().context("stdout")?;
    let mut stderr = child.stderr.take().context("stderr")?;

    let tx_out = tx.clone();
    let out_task = tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            match stdout.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx_out.send(chunk_stdout(buf[..n].to_vec())).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    let tx_err = tx.clone();
    let err_task = tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            match stderr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx_err.send(chunk_stderr(buf[..n].to_vec())).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    tokio::spawn(async move {
        while let Some(Ok(c)) = inbound.next().await {
            if let Some(Kind::Stdin(b)) = c.kind {
                use tokio::io::AsyncWriteExt;
                if stdin.write_all(&b).await.is_err() {
                    break;
                }
            }
        }
    });

    tokio::spawn(async move {
        let code = child
            .wait()
            .await
            .map(|s| s.code().unwrap_or(1))
            .unwrap_or(1);
        let _ = out_task.await;
        let _ = err_task.await;
        let _ = tx.send(chunk_exit(code)).await;
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start(user: &str, argv: &[&str]) -> ExecStart {
        ExecStart {
            pod: "dev".into(),
            user: user.into(),
            argv: argv.iter().map(|s| s.to_string()).collect(),
            tty: false,
            rows: 0,
            cols: 0,
            env: vec!["TERM=xterm".into()],
        }
    }

    #[test]
    fn argv_root_cmd() {
        let a = exec_argv(42, Path::new("/nonexistent"), &start("root", &["echo", "hi"])).unwrap();
        let s: Vec<&str> = a.iter().map(|o| o.to_str().unwrap()).collect();
        assert!(s.starts_with(&[
            "nsenter", "--target", "42", "--mount", "--uts", "--ipc", "--net", "--pid", "--"
        ]));
        assert!(!s.iter().any(|x| *x == "setpriv"), "root gets no setpriv");
        assert!(s.iter().any(|x| *x == "HOME=/root"));
        assert!(s.ends_with(&["echo", "hi"]));
    }

    #[test]
    fn argv_user_login_shell() {
        let dir = std::env::temp_dir().join("rp-exec-test");
        std::fs::create_dir_all(dir.join("etc")).unwrap();
        std::fs::write(
            dir.join("etc/passwd"),
            "root:x:0:0::/root:/bin/bash\nnick:x:1000:1000::/home/nick:/bin/bash\n",
        )
        .unwrap();
        let a = exec_argv(7, &dir, &start("nick", &[])).unwrap();
        let s: Vec<&str> = a.iter().map(|o| o.to_str().unwrap()).collect();
        assert!(s.iter().any(|x| *x == "--reuid=1000"));
        assert!(s.iter().any(|x| *x == "HOME=/home/nick"));
        assert!(s.iter().any(|x| *x == "/bin/bash"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
