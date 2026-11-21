//! Guest-only synthetic DNS server and truthful finish/drain receipts.
//! Response construction lives in the independent Hickory fixture model.

use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use futures::{FutureExt, StreamExt};
use hickory_net::{
    runtime::iocompat::AsyncIoTokioAsStd, tcp::TcpStream as DnsTcpStream, xfer::DnsStreamHandle,
};
use hickory_proto::{
    op::{Message, SerialMessage},
    serialize::binary::{BinDecodable, BinDecoder},
};
use serde_json::{Value, json};
use tokio::{
    net::{TcpListener, TcpStream, UdpSocket},
    sync::watch,
    task::JoinSet,
};

use super::fixture::{self, Protocol, Role};

pub struct ServerConfig {
    pub role: Role,
    pub addresses: Vec<IpAddr>,
    pub port: u16,
    pub output: PathBuf,
    pub finish: PathBuf,
    pub token: String,
    pub drain: Duration,
}

struct Ledger {
    output: PathBuf,
    token: String,
    start: Instant,
    next: AtomicU64,
    events: Mutex<File>,
}

impl Ledger {
    fn event(&self, mut event: Value) -> io::Result<u64> {
        let mut file = self
            .events
            .lock()
            .map_err(|_| io::Error::other("fixture ledger poisoned"))?;
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        event["event_id"] = id.into();
        event["token"] = self.token.clone().into();
        event["elapsed_ns"] = self.start.elapsed().as_nanos().to_string().into();
        serde_json::to_writer(&mut *file, &event)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        Ok(id)
    }

    fn bytes(&self, id: u64, kind: &str, bytes: &[u8]) -> io::Result<()> {
        let path = self.output.join(format!("{id}-{kind}.dns"));
        let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
        file.write_all(bytes)?;
        file.sync_all()
    }
}

fn decode(bytes: &[u8]) -> io::Result<Message> {
    let mut decoder = BinDecoder::new(bytes);
    let message = Message::read(&mut decoder).map_err(io::Error::other)?;
    if !decoder.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailing DNS bytes",
        ));
    }
    Ok(message)
}

fn build_reply(
    bytes: &[u8],
    role: Role,
    protocol: Protocol,
    ledger: &Ledger,
    peer: SocketAddr,
    connection: Option<u64>,
) -> io::Result<Option<(u64, Vec<u8>)>> {
    let id = ledger.event(json!({"kind":"query", "role":format!("{role:?}"), "protocol":format!("{protocol:?}"), "peer":peer.to_string(), "connection":connection, "bytes":bytes.len()}))?;
    ledger.bytes(id, "query", bytes)?;
    let request = match decode(bytes) {
        Ok(request) => request,
        Err(error) => {
            ledger.event(json!({"kind":"malformed", "query":id, "reason":error.to_string()}))?;
            return Ok(None);
        }
    };
    let Some(response) = fixture::answer(&request, role, protocol) else {
        ledger.event(json!({"kind":"silent", "query":id}))?;
        return Ok(None);
    };
    let reply = response.to_vec().map_err(io::Error::other)?;
    ledger.bytes(id, "reply", &reply)?;
    ledger.event(json!({"kind":"reply-built", "query":id, "transaction":request.metadata.id, "bytes":reply.len()}))?;
    Ok(Some((id, reply)))
}

async fn udp(
    socket: UdpSocket,
    role: Role,
    ledger: Arc<Ledger>,
    mut stop: watch::Receiver<bool>,
) -> io::Result<bool> {
    let mut buffer = vec![0; u16::MAX as usize];
    let mut stopping = false;
    loop {
        let incoming = if stopping {
            match socket.try_recv_from(&mut buffer) {
                Ok(incoming) => Some(incoming),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => None,
                Err(error) => return Err(error),
            }
        } else {
            tokio::select! {
                biased;
                _ = stop.changed() => { stopping = true; continue; }
                incoming = socket.recv_from(&mut buffer) => Some(incoming?),
            }
        };
        let Some((length, peer)) = incoming else {
            ledger
                .event(json!({"kind":"udp-drained", "local":socket.local_addr()?.to_string()}))?;
            return Ok(true);
        };
        if let Some((query, reply)) =
            build_reply(&buffer[..length], role, Protocol::Udp, &ledger, peer, None)?
        {
            let sent = socket.send_to(&reply, peer).await?;
            ledger.event(json!({"kind":"udp-send", "query":query, "peer":peer.to_string(), "sent":sent, "expected":reply.len()}))?;
            if sent != reply.len() {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "partial fixture datagram",
                ));
            }
        }
    }
}

async fn tcp_client(
    socket: TcpStream,
    peer: SocketAddr,
    role: Role,
    ledger: Arc<Ledger>,
) -> io::Result<()> {
    let connection = ledger.event(json!({"kind":"tcp-accept", "peer":peer.to_string(), "local":socket.local_addr()?.to_string()}))?;
    let (mut stream, mut sender) = DnsTcpStream::from_stream(AsyncIoTokioAsStd(socket), peer);
    while let Some(incoming) = stream.next().await {
        let incoming = incoming?;
        if let Some((query, reply)) = build_reply(
            incoming.bytes(),
            role,
            Protocol::Tcp,
            &ledger,
            peer,
            Some(connection),
        )? {
            let size = reply.len();
            sender
                .send(SerialMessage::new(reply, peer))
                .map_err(io::Error::other)?;
            // The handle only queues; the next stream poll drives framing and
            // flush. Never describe this event as a completed physical send.
            ledger.event(json!({"kind":"tcp-reply-queued", "query":query, "connection":connection, "bytes":size}))?;
        }
    }
    ledger.event(json!({"kind":"tcp-eof", "connection":connection}))?;
    Ok(())
}

async fn tcp(
    listener: TcpListener,
    role: Role,
    ledger: Arc<Ledger>,
    mut stop: watch::Receiver<bool>,
    drain: Duration,
) -> io::Result<bool> {
    let mut clients = JoinSet::new();
    let mut complete = true;
    loop {
        tokio::select! {
            biased;
            _ = stop.changed() => break,
            accepted = listener.accept() => {
                let (socket, peer) = accepted?;
                clients.spawn(tcp_client(socket, peer, role, ledger.clone()));
            }
            outcome = clients.join_next(), if !clients.is_empty() => {
                if !matches!(outcome, Some(Ok(Ok(())))) { complete = false; }
            }
        }
    }
    // Poll each pending accept, including a TCP-only ready queue. Sender-stop
    // custody is supplied in the matched finish token before this drain begins.
    while let Some(accepted) = listener.accept().now_or_never() {
        let (socket, peer) = accepted?;
        clients.spawn(tcp_client(socket, peer, role, ledger.clone()));
    }
    let deadline = tokio::time::Instant::now() + drain;
    while !clients.is_empty() {
        match tokio::time::timeout_at(deadline, clients.join_next()).await {
            Ok(Some(Ok(Ok(())))) => (),
            Ok(_) => complete = false,
            Err(_) => {
                complete = false;
                ledger
                    .event(json!({"kind":"tcp-drain-incomplete", "connections":clients.len()}))?;
                clients.abort_all();
                while clients.join_next().await.is_some() {}
            }
        }
    }
    ledger.event(json!({"kind":"tcp-drained", "local":listener.local_addr()?.to_string(), "complete":complete}))?;
    Ok(complete)
}

fn private_json(path: &Path, value: &Value) -> io::Result<()> {
    let staging = path.with_extension("json.next");
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&staging)?;
    serde_json::to_writer(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    // Same-directory publication is atomic and refuses an existing final
    // receipt. Readers cannot mistake a partially serialized JSON file for a
    // complete readiness, finish or terminal record.
    std::fs::hard_link(&staging, path)?;
    std::fs::remove_file(staging)?;
    File::open(
        path.parent()
            .ok_or_else(|| io::Error::other("receipt has no parent"))?,
    )?
    .sync_all()
}

pub fn publish_finish(path: &Path, token: &str) -> io::Result<()> {
    private_json(path, &json!({"token":token, "senders_stopped":true}))
}

pub async fn run(config: ServerConfig) -> io::Result<bool> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir(&config.output)?;
    std::fs::set_permissions(&config.output, std::fs::Permissions::from_mode(0o700))?;
    if config.finish.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "stale fixture finish file",
        ));
    }
    let ledger = Arc::new(Ledger {
        output: config.output.clone(),
        token: config.token.clone(),
        start: Instant::now(),
        next: AtomicU64::new(1),
        events: Mutex::new(
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(config.output.join("events.jsonl"))?,
        ),
    });
    let (stop, stopping) = watch::channel(false);
    let mut listeners = JoinSet::new();
    let mut addresses = Vec::new();
    // Bind every endpoint before advertising readiness; partial bind failure
    // starts no listener and preserves the failure directory.
    let mut bound = Vec::new();
    for address in &config.addresses {
        let socket = UdpSocket::bind(SocketAddr::new(*address, config.port)).await?;
        let endpoint = socket.local_addr()?;
        let listener = TcpListener::bind(endpoint).await?;
        addresses.push(endpoint.to_string());
        bound.push((socket, listener));
    }
    for (socket, listener) in bound {
        listeners.spawn(udp(socket, config.role, ledger.clone(), stopping.clone()));
        listeners.spawn(tcp(
            listener,
            config.role,
            ledger.clone(),
            stopping.clone(),
            config.drain,
        ));
    }
    private_json(
        &config.output.join("ready.json"),
        &json!({"token":config.token, "addresses":addresses, "role":format!("{:?}", config.role)}),
    )?;
    let stop_result = loop {
        tokio::select! {
            outcome = listeners.join_next() => {
                break Err(io::Error::other(format!("fixture listener ended before finish: {outcome:?}")));
            }
            _ = tokio::time::sleep(Duration::from_millis(50)) => {
                match std::fs::read(&config.finish) {
                    Err(error) if error.kind() == io::ErrorKind::NotFound => (),
                    Err(error) => break Err(error),
                    Ok(bytes) => {
                        let parsed = serde_json::from_slice::<Value>(&bytes);
                        if matches!(&parsed, Ok(value) if value["token"] == config.token && value["senders_stopped"] == true) {
                            break Ok(());
                        }
                        break Err(io::Error::new(io::ErrorKind::InvalidData, "unmatched fixture finish custody"));
                    }
                }
            }
        }
    };
    stop.send_replace(true);
    let mut complete = stop_result.is_ok();
    while let Some(outcome) = listeners.join_next().await {
        complete &= matches!(outcome, Ok(Ok(true)));
    }
    private_json(
        &config.output.join("terminal.json"),
        &json!({"token":config.token, "complete":complete, "finish_error":stop_result.err().map(|error| error.to_string())}),
    )?;
    Ok(complete)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::{
        op::Query,
        rr::{Name, RData, RecordType, rdata::A},
    };

    async fn start_case(
        label: &str,
        drain: Duration,
    ) -> (
        PathBuf,
        SocketAddr,
        tokio::task::JoinHandle<io::Result<bool>>,
    ) {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let root = std::env::temp_dir().join(format!(
            "krtek-dns-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let config = ServerConfig {
            role: Role::Home,
            addresses: vec!["127.0.0.1".parse().unwrap()],
            port: 0,
            output: root.join("server"),
            finish: root.join("finish.json"),
            token: label.into(),
            drain,
        };
        let server = tokio::spawn(run(config));
        let ready = root.join("server/ready.json");
        let value = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Ok(bytes) = std::fs::read(&ready) {
                    break serde_json::from_slice::<Value>(&bytes).unwrap();
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        let peer = value["addresses"][0].as_str().unwrap().parse().unwrap();
        (root, peer, server)
    }

    fn question(owner: &str) -> Message {
        let mut request = Message::query();
        request.add_query(Query::query(
            Name::from_ascii(owner).unwrap(),
            RecordType::A,
        ));
        request
    }

    #[tokio::test]
    async fn fixture_server_udp_tcp_bytes_and_natural_finish_reach_the_client() {
        let (root, peer, server) = start_case("complete", Duration::from_secs(1)).await;
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let request = question("udp-nonce.home.");
        socket
            .send_to(&request.to_vec().unwrap(), peer)
            .await
            .unwrap();
        let mut bytes = vec![0; u16::MAX as usize];
        let (length, source) =
            tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut bytes))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(source, peer);
        let reply = decode(&bytes[..length]).unwrap();
        assert_eq!(reply.metadata.id, request.metadata.id);
        assert_eq!(reply.answers[0].data, RData::A(A::new(10, 77, 10, 1)));
        drop(socket);
        let stream = TcpStream::connect(peer).await.unwrap();
        let (mut stream, mut sender) = DnsTcpStream::from_stream(AsyncIoTokioAsStd(stream), peer);
        for owner in ["first.home.", "unlisted.example.", "second.home."] {
            let request = question(owner);
            sender
                .send(SerialMessage::new(request.to_vec().unwrap(), peer))
                .unwrap();
            let received = tokio::time::timeout(Duration::from_secs(2), stream.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let reply = decode(received.bytes()).unwrap();
            assert_eq!(reply.queries, request.queries);
            assert_eq!(reply.metadata.id, request.metadata.id);
        }
        drop(sender);
        drop(stream);
        publish_finish(&root.join("finish.json"), "complete").unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(3), server)
                .await
                .unwrap()
                .unwrap()
                .unwrap()
        );
        let terminal: Value =
            serde_json::from_slice(&std::fs::read(root.join("server/terminal.json")).unwrap())
                .unwrap();
        assert_eq!(terminal["complete"], true);
        let events = std::fs::read_to_string(root.join("server/events.jsonl")).unwrap();
        assert!(
            events.contains("udp-drained")
                && events.contains("tcp-eof")
                && events.contains("tcp-reply-queued")
        );
        assert!(!events.contains("tcp-drain-incomplete"));
        let saved = std::fs::read_dir(root.join("server"))
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "dns"))
            .count();
        assert_eq!(saved, 8); // Four full queries and four full replies.
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn fixture_server_pending_tcp_accept_or_idle_stream_cannot_claim_complete() {
        let (root, peer, server) = start_case("incomplete", Duration::from_millis(50)).await;
        let client = TcpStream::connect(peer).await.unwrap();
        publish_finish(&root.join("finish.json"), "incomplete").unwrap();
        assert!(
            !tokio::time::timeout(Duration::from_secs(3), server)
                .await
                .unwrap()
                .unwrap()
                .unwrap()
        );
        let events = std::fs::read_to_string(root.join("server/events.jsonl")).unwrap();
        assert!(events.contains("tcp-accept") && events.contains("tcp-drain-incomplete"));
        assert!(!events.contains("tcp-eof"));
        drop(client);
        std::fs::remove_dir_all(root).unwrap();
    }
}
