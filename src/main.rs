mod autoscaler;
mod daemon;
mod dns;
mod docker;
mod firewall;
mod manifest;
mod node_pool;
mod dashboard;
mod proxy;
mod registry;

use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
#[command(name = "mini-k8s", about = "Local container orchestrator")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Start the cluster daemon
    Up {
        #[arg(short, long, default_value = "manifest.yaml")]
        manifest: String,
    },
    /// Tear down the cluster (stop all containers, remove networks)
    Down {
        #[arg(short, long, default_value = "manifest.yaml")]
        manifest: String,
    },
    /// Show cluster status
    Status {
        #[arg(short, long, default_value = "manifest.yaml")]
        manifest: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Up { manifest } => {
            let m = manifest::load_manifest(&manifest)?;
            daemon::run_daemon(m).await?;
        }
        Commands::Down { manifest } => {
            let m = manifest::load_manifest(&manifest)?;
            daemon::teardown(&m).await?;
        }
        Commands::Status { manifest } => {
            let m = manifest::load_manifest(&manifest)?;
            daemon::status(&m).await?;
        }
    }

    Ok(())
}
