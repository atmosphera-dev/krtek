//! Synthetic non-recursive DNS fixture. Run only inside the assigned test guest.

use std::{net::IpAddr, path::PathBuf, time::Duration};

use clap::{Parser, Subcommand, ValueEnum};

#[path = "../../scripts/split_dns_fixture.rs"]
mod fixture;
#[path = "../../scripts/split_dns_server.rs"]
mod server;

#[derive(Clone, Copy, ValueEnum)]
enum Role {
    Home,
    Ordinary,
}

#[derive(Parser)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Serve(ServerArguments),
    /// Call only after the matched test senders have stopped.
    Finish {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        token: String,
    },
}

#[derive(clap::Args)]
struct ServerArguments {
    #[arg(long, value_enum)]
    role: Role,
    #[arg(long, required = true)]
    address: Vec<IpAddr>,
    #[arg(long, default_value_t = 53)]
    port: u16,
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    finish: PathBuf,
    #[arg(long)]
    token: String,
    #[arg(long, default_value_t = 10)]
    drain_seconds: u64,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    match Arguments::parse().command {
        Command::Serve(args) => serve(args).await,
        Command::Finish { path, token } => server::publish_finish(&path, &token),
    }
}

async fn serve(args: ServerArguments) -> std::io::Result<()> {
    if args.address.iter().any(|address| {
        ![
            "10.77.10.53".parse::<IpAddr>().unwrap(),
            "10.77.10.54".parse().unwrap(),
            "fd71:7274:656b:10::53".parse().unwrap(),
            "fd71:7274:656b:10::54".parse().unwrap(),
        ]
        .contains(address)
    }) {
        return Err(std::io::Error::other(
            "fixture requires the run-11 TAP address",
        ));
    }
    let complete = server::run(server::ServerConfig {
        role: match args.role {
            Role::Home => fixture::Role::Home,
            Role::Ordinary => fixture::Role::Ordinary,
        },
        addresses: args.address,
        port: args.port,
        output: args.output,
        finish: args.finish,
        token: args.token,
        drain: Duration::from_secs(args.drain_seconds),
    })
    .await?;
    if complete {
        Ok(())
    } else {
        Err(std::io::Error::other(
            "fixture observation window is incomplete",
        ))
    }
}
