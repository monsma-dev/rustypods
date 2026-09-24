use super::*;

pub(crate) async fn run(mut cli: Cli) -> Result<()> {
    let cmd = cli.cmd.take().unwrap();
    match cmd {
        Cmd::Cp { src, dst, user } => {
            cp_cmd(cli.socket, cli.remote, src, dst, user).await?;
        }
        Cmd::Images => {
            let l = connect(cli.socket.clone(), cli.remote.clone())
                .await?
                .list_images(ListImagesRequest {})
                .await?
                .into_inner();
            for i in &l.images {
                let mut extra = String::new();
                if !i.entrypoint.is_empty() || !i.cmd.is_empty() {
                    extra = format!(
                        "  run: {}",
                        i.entrypoint
                            .iter()
                            .chain(i.cmd.iter())
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(" ")
                    );
                }
                println!("{:<20} {:<28} {}{}", i.name, i.source, i.path, extra);
            }
            if l.images.is_empty() {
                println!("no images — `rustypods pull busybox:latest` or `rustypods import --from-distrobox arch`");
            }
        }
        Cmd::Pull {
            reference,
            name,
            strip_setuid,
        } => {
            println!("pulling {reference} (this can take a while)...");
            // Pulls routinely outlast the default 30s call bound.
            let img =
                rustypods_client::connect_timeout(cli.socket.clone(), cli.remote.clone(), LONG_RPC)
                    .await?
                    .pull_image(PullImageRequest {
                        reference,
                        name: name.unwrap_or_default(),
                        strip_setuid,
                    })
                    .await?
                    .into_inner();
            println!("image {} → {}", img.name, img.path);
            if !img.entrypoint.is_empty() || !img.cmd.is_empty() {
                println!(
                    "  runs non-boot: {}",
                    img.entrypoint
                        .iter()
                        .chain(img.cmd.iter())
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(" ")
                );
            }
        }
        Cmd::Import {
            from_distrobox,
            name,
            user,
        } => {
            let name = name.unwrap_or_else(|| format!("{from_distrobox}-base"));
            let user = match user {
                Some(u) => u,
                None => current_username()?,
            };
            println!("exporting: {from_distrobox} → {name} (this can take a while)...");
            let img =
                rustypods_client::connect_timeout(cli.socket.clone(), cli.remote.clone(), LONG_RPC)
                    .await?
                    .import_image(ImportImageRequest {
                        name: name.clone(),
                        distrobox: from_distrobox,
                        import_user: user,
                    })
                    .await?
                    .into_inner();
            println!("image {} → {}", img.name, img.path);
        }
        Cmd::Rmi { name } => {
            if !confirm_destructive(cli.yes, &format!("Remove image {name}?"))? {
                println!("aborted");
                return Ok(());
            }
            connect(cli.socket.clone(), cli.remote.clone())
                .await?
                .remove_image(ImageRef { name: name.clone() })
                .await?;
            println!("image {name} removed");
        }
        Cmd::Export {
            pod,
            output,
            format,
            allow_inconsistent,
        } => {
            let mut c = connect_timeout(cli.socket.clone(), cli.remote.clone(), LONG_RPC).await?;
            let mut stream = c
                .export_pod(ExportRequest {
                    name: pod.clone(),
                    format: format.unwrap_or_default(),
                    allow_inconsistent,
                })
                .await?
                .into_inner();
            use tokio::io::AsyncWriteExt;
            let mut out: Box<dyn tokio::io::AsyncWrite + Unpin> = match &output {
                Some(p) => Box::new(
                    tokio::fs::File::create(p)
                        .await
                        .with_context(|| format!("create {}", p.display()))?,
                ),
                None => Box::new(tokio::io::stdout()),
            };
            let write = async {
                let mut total = 0u64;
                let mut progress = Progress::new();
                while let Some(chunk) = stream.next().await {
                    let chunk = chunk?;
                    if !chunk.warning.is_empty() {
                        progress.done(&format!("warning: {}", chunk.warning));
                    }
                    if chunk.data.is_empty() {
                        continue;
                    }
                    total += chunk.data.len() as u64;
                    out.write_all(&chunk.data).await?;
                    progress.tick(|| format!("exporting {pod}: {}", fmt_bytes(total)));
                }
                out.flush().await?;
                progress.done(&format!("exported {pod}: {}", fmt_bytes(total)));
                Ok::<(), anyhow::Error>(())
            }
            .await;
            if let Err(e) = write {
                if let Some(p) = &output {
                    match tokio::fs::remove_file(p).await {
                        Ok(()) => eprintln!("removed partial archive {}", p.display()),
                        Err(rm) => eprintln!(
                            "warning: failed to remove partial archive {}: {rm}",
                            p.display()
                        ),
                    }
                }
                return Err(e);
            }
        }
        Cmd::Load { file, name, trust } => {
            // The unary reply only lands after the full upload — the
            // default 30s call timeout would cut big archives mid-send.
            let mut c = connect_timeout(cli.socket.clone(), cli.remote.clone(), LONG_RPC).await?;
            use rustypods_proto::rpc::import_chunk::Kind;
            // Open before the RPC so a missing file errors locally.
            let mut input: Box<dyn tokio::io::AsyncRead + Unpin + Send> = if file == "-" {
                Box::new(tokio::io::stdin())
            } else {
                Box::new(
                    tokio::fs::File::open(&file)
                        .await
                        .with_context(|| format!("open {file}"))?,
                )
            };
            let (tx, rx) = tokio::sync::mpsc::channel::<ImportChunk>(8);
            tokio::spawn(async move {
                if name.is_some() || trust {
                    let _ = tx
                        .send(ImportChunk {
                            kind: Some(Kind::Options(ImportOptions {
                                rename: name.unwrap_or_default(),
                                trust,
                            })),
                        })
                        .await;
                }
                use tokio::io::AsyncReadExt;
                let mut buf = vec![0u8; 1 << 20];
                let mut total = 0u64;
                let mut progress = Progress::new();
                loop {
                    match input.read(&mut buf).await {
                        Ok(0) => {
                            progress.done(&format!("uploaded: {}", fmt_bytes(total)));
                            break;
                        }
                        Ok(n) => {
                            total += n as u64;
                            progress.tick(|| format!("uploading: {}", fmt_bytes(total)));
                            if tx
                                .send(ImportChunk {
                                    kind: Some(Kind::Data(buf[..n].to_vec())),
                                })
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(e) => {
                            progress.done(&format!("read error after {}: {e}", fmt_bytes(total)));
                            break;
                        }
                    }
                }
            });
            let pod = c
                .import_pod(tokio_stream::wrappers::ReceiverStream::new(rx))
                .await?
                .into_inner();
            eprintln!("imported {} ({})", pod.name, pod.rootfs);
            for n in &pod.notes {
                eprintln!("import: {n}");
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}
