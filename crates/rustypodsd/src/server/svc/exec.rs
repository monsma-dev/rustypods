use super::super::*;

impl super::super::Svc {
    /// Run a non-tty exec session to completion and capture its output —
    /// the REST exec endpoint's engine. `dur` bounds wall time: on
    /// timeout we drop the receiver, exec::run's waiter sees
    /// tx.closed() and kills the nsenter'd child.
    pub(crate) async fn exec_collect(
        &self,
        start: ExecStart,
        max_bytes: usize,
        dur: std::time::Duration,
    ) -> Result<ExecOutcome, Status> {
        let name = proto::validate_name(&start.pod).map_err(bad)?.to_string();
        let (private_users, allow_setuid) = {
            let st = self.st.lock().await;
            let Some(m) = st.pods.get(&name) else {
                return Err(Status::not_found(format!("pod {name} not found")));
            };
            (m.private_users, m.allow_setuid)
        };
        let Some(leader) = self.engine.running_pid(&name).await else {
            return Err(Status::failed_precondition(format!(
                "pod {name} is not running"
            )));
        };
        if leader == 0 {
            return Err(Status::failed_precondition(format!(
                "pod {name} is still booting — no leader pid yet"
            )));
        }
        proto::validate_argv(&start.argv).map_err(bad)?;
        proto::validate_env(&start.env).map_err(bad)?;
        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        crate::exec::run(
            start,
            &self.pod_rootfs(&name),
            leader,
            private_users,
            allow_setuid,
            tokio_stream::empty(),
            tx,
        )
        .await
        .map_err(int)?;
        let deadline = tokio::time::Instant::now() + dur;
        let mut out = ExecOutcome::default();
        loop {
            let chunk = match tokio::time::timeout_at(deadline, rx.recv()).await {
                Err(_) => {
                    out.timed_out = true;
                    drop(rx); // tx.closed() → the waiter kills the child
                    break;
                }
                Ok(None) => break,
                Ok(Some(c)) => c,
            };
            match chunk.map(|c| c.kind) {
                Ok(Some(rustypods_proto::rpc::exec_chunk::Kind::Stdout(b))) => {
                    out.push_stdout(b, max_bytes)
                }
                Ok(Some(rustypods_proto::rpc::exec_chunk::Kind::Stderr(b))) => {
                    out.push_stderr(b, max_bytes)
                }
                Ok(Some(rustypods_proto::rpc::exec_chunk::Kind::Exit(e))) => {
                    out.exit_code = Some(e.code);
                    break;
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        Ok(out)
    }
}
