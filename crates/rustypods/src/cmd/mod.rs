mod cluster;
mod lifecycle;
mod transfer;

use super::*;

pub(crate) async fn dispatch(cli: Cli) -> Result<()> {
    let group = match cli.cmd.as_ref() {
        None => {
            Cli::command().print_long_help()?;
            std::process::exit(2);
        }
        Some(
            Cmd::Create { .. }
            | Cmd::Start { .. }
            | Cmd::Stop { .. }
            | Cmd::Restart { .. }
            | Cmd::Ps
            | Cmd::Destroy { .. }
            | Cmd::Clone { .. }
            | Cmd::Commit { .. }
            | Cmd::Rollback { .. }
            | Cmd::Snapshots { .. }
            | Cmd::Rmsnap { .. }
            | Cmd::Config { .. }
            | Cmd::Reload { .. },
        ) => 0,
        Some(
            Cmd::Images
            | Cmd::Pull { .. }
            | Cmd::Import { .. }
            | Cmd::Rmi { .. }
            | Cmd::Export { .. }
            | Cmd::Load { .. }
            | Cmd::Cp { .. },
        ) => 1,
        Some(_) => 2,
    };
    match group {
        0 => lifecycle::run(cli).await,
        1 => transfer::run(cli).await,
        _ => cluster::run(cli).await,
    }
}
