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
    /// Independent complete query/Home-response goldens for the ordinary-UID
    /// connected TCP consumer. Run in the device guest, never on the host.
    TcpVectors {
        #[arg(long)]
        nonce: String,
        #[arg(long)]
        id: u16,
        #[arg(long)]
        system: bool,
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
        Command::TcpVectors { nonce, id, system } => {
            println!("{}", tcp_vectors_for(&nonce, id, system)?);
            Ok(())
        }
    }
}

/// Stub-resolver queries, as an app's resolver sends them: recursion desired. A real
/// ordinary resolver refuses non-recursive questions, and Home goldens echo the flag.
#[cfg(test)]
fn tcp_vectors(nonce: &str, id: u16) -> std::io::Result<serde_json::Value> {
    tcp_vectors_for(nonce, id, false)
}
fn tcp_vectors_for(nonce: &str, id: u16, system: bool) -> std::io::Result<serde_json::Value> {
    use hickory_proto::{
        op::{Message, Query},
        rr::{Name, RecordType},
    };
    if nonce.is_empty()
        || nonce.len() > 40
        || !nonce.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(std::io::Error::other(
            "an alphanumeric DNS-label nonce is required",
        ));
    }
    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let mut vectors = Vec::new();
    for (offset, (name, home)) in [
        (format!("{nonce}-first.home."), true),
        (
            if system {
                format!("{nonce}.ordinary.test.")
            } else {
                "example.com.".into()
            },
            false,
        ),
        (format!("{nonce}-last.home."), true),
    ]
    .into_iter()
    .enumerate()
    {
        let mut request = Message::query();
        request.metadata.id = id.wrapping_add(offset as u16);
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(
            Name::from_ascii(name).map_err(std::io::Error::other)?,
            RecordType::A,
        ));
        let query = request.to_vec().map_err(std::io::Error::other)?;
        let expected = (home || system).then(|| {
            fixture::answer(
                &request,
                if home {
                    fixture::Role::Home
                } else {
                    fixture::Role::Ordinary
                },
                fixture::Protocol::Tcp,
            )
            .unwrap()
            .to_vec()
            .unwrap()
        });
        vectors.push(serde_json::json!({"query_hex":hex(&query), "expected_hex":expected.map(|bytes| hex(&bytes)), "home":home}));
    }
    Ok(serde_json::json!({"messages":vectors}))
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

#[cfg(test)]
mod tests {
    #[test]
    fn partial_tcp_vectors_keep_a_distinct_exact_ordinary_answer() {
        let vectors = super::tcp_vectors_for("systemControl", 65535, true).unwrap();
        let messages = vectors["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 3);
        assert!(!messages[1]["home"].as_bool().unwrap());
        assert!(
            messages
                .iter()
                .all(|message| message["expected_hex"].as_str().is_some())
        );
        assert_ne!(messages[0]["expected_hex"], messages[1]["expected_hex"]);
    }
    use hickory_proto::op::{Message, MessageType};

    fn decode(hex: &str) -> Message {
        let bytes = (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
            .collect::<Vec<_>>();
        Message::from_vec(&bytes).unwrap()
    }

    #[test]
    fn tcp_vectors_ask_for_recursion_and_home_goldens_echo_it() {
        let vectors = super::tcp_vectors("rdControl", 65535).unwrap();
        let messages = vectors["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 3);
        for (index, vector) in messages.iter().enumerate() {
            let query = decode(vector["query_hex"].as_str().unwrap());
            assert_eq!(query.metadata.message_type, MessageType::Query);
            assert!(query.metadata.recursion_desired, "query {index}");
            assert_eq!(query.metadata.id, 65535u16.wrapping_add(index as u16));
            match vector["expected_hex"].as_str() {
                Some(expected) => {
                    let reply = decode(expected);
                    assert!(vector["home"].as_bool().unwrap());
                    assert!(reply.metadata.recursion_desired, "golden {index}");
                    assert_eq!(reply.metadata.id, query.metadata.id);
                }
                None => assert!(!vector["home"].as_bool().unwrap()),
            }
        }
    }
}
