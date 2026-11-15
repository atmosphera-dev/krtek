//! Scheduling gates wrap the existing adapter/crypto peer only in this fixture.
use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use talpid_netstack::address_translation::Direction;
use talpid_types::relay_flow::{RelayBufferAllocator, RelayBufferReservation, RelayFlowError};

struct Gate {
    enabled: AtomicBool,
    held: AtomicUsize,
    changed: tokio::sync::Notify,
    permits: tokio::sync::Semaphore,
}
impl Default for Gate {
    fn default() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            held: AtomicUsize::new(0),
            changed: tokio::sync::Notify::new(),
            permits: tokio::sync::Semaphore::new(0),
        }
    }
}
impl Gate {
    async fn held_after(&self, previous: usize) -> usize {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let wake = self.changed.notified();
                let count = self.held.load(Ordering::Acquire);
                if count > previous {
                    return count;
                }
                wake.await;
            }
        })
        .await
        .expect("adapter did not reach the held handoff")
    }
}
struct GatedReceive {
    receive: ManagedReceive,
    gate: Arc<Gate>,
}
impl IpRecv for GatedReceive {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        let packet = self
            .receive
            .recv(pool)
            .await?
            .next()
            .ok_or_else(unavailable)?;
        if self.gate.enabled.load(Ordering::Acquire) {
            self.gate.held.fetch_add(1, Ordering::Release);
            self.gate.changed.notify_one();
            self.gate
                .permits
                .acquire()
                .await
                .map_err(|_| unavailable())?
                .forget();
        }
        Ok(std::iter::once(packet))
    }
    fn mtu(&self) -> MtuWatcher {
        self.receive.mtu()
    }
}
struct GatedTunnel {
    device: Device<(TransportFactory, ManagedSend, SourceFilter<GatedReceive>)>,
    owner: Arc<ManagedControl>,
    gate: Arc<Gate>,
}
#[async_trait::async_trait]
impl Tunnel for GatedTunnel {
    fn get_interface_name(&self) -> String {
        self.owner.interface()
    }
    fn stop(self: Box<Self>) -> Result<(), TunnelError> {
        panic!("fixture uses joined shutdown")
    }
    async fn get_tunnel_stats(&self) -> Result<crate::stats::StatsMap, TunnelError> {
        Ok(self
            .device
            .read(async |device| device.peers().await)
            .await
            .into_iter()
            .map(|peer| {
                (
                    peer.peer.public_key.to_bytes(),
                    crate::stats::Stats::from(peer.stats),
                )
            })
            .collect())
    }
}
impl GatedTunnel {
    async fn new(mut pending: PendingManaged, config: &Config) -> Self {
        let pair = pending.create(config).await.unwrap();
        let gate = Arc::new(Gate::default());
        let device = DeviceBuilder::new()
            .with_udp(transport_factory(
                true,
                None,
                config.entry_peer.endpoint,
                Arc::new(NoopBypass),
            ))
            .with_private_key(StaticSecret::from(config.tunnel.private_key.to_bytes()))
            .with_peer(to_gotatun_peer(&config.entry_peer, None))
            .with_ip_pair(
                pair.send,
                SourceFilter::new(
                    GatedReceive {
                        receive: pair.receive,
                        gate: gate.clone(),
                    },
                    config.tunnel_ipv4(),
                    config.tunnel_ipv6(),
                ),
            )
            .build()
            .await
            .unwrap();
        pair.owner.installed();
        pair.owner.activate().unwrap();
        Self {
            device,
            owner: pair.owner,
            gate,
        }
    }
    async fn check(&self) -> Check {
        let (_cancel, receiver) = CancelToken::new();
        let mut check = Check::new_with_smoltcp(self.owner.pinger().unwrap(), 0, receiver);
        crate::establish_and_activate(
            &mut check,
            self,
            Some(&self.owner),
            async { Ok(()) },
            |()| (),
        )
        .await
        .unwrap();
        private_done(&self.owner, 0).await;
        check
    }
    async fn shutdown(self) {
        self.owner.revoke();
        self.gate.permits.close();
        self.device.stop().await;
        self.owner.stop().await;
    }
}
async fn private_done(owner: &ManagedControl, previous: u64) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            {
                let ledger = owner.ledger.lock().unwrap();
                if ledger.highest > previous && ledger.live.is_empty() {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("private authenticated consumer was starved");
}
fn oversize(config: &Config, inbound: bool, nonce: u8) -> Vec<u8> {
    let mut packet = packet(config, false, 17, &vec![nonce; 1600], inbound, false);
    if inbound {
        packet = application_reply(&packet);
    }
    packet[6] = 0x40;
    fix_wire(&mut packet, 20, 17);
    packet
}
fn available(allocator: &dyn RelayBufferAllocator) -> usize {
    let (mut low, mut high) = (0usize, 22 * 1024 * 1024usize);
    while low < high {
        let n = low + (high - low).div_ceil(2);
        if allocator.try_reserve(n).is_ok() {
            low = n;
        } else {
            high = n - 1;
        }
    }
    low
}
async fn inject(input: &mpsc::Sender<Packet<Ip>>, bytes: &[u8]) {
    input
        .send(Packet::<[u8]>::copy_from(bytes).try_into_ip().unwrap())
        .await
        .unwrap();
}
#[cfg(unix)]
#[tokio::test]
async fn pressure_preserves_ordinary_and_private_consumer_progress() {
    use futures::FutureExt;
    use talpid_tunnel::packet_attachment::PACKET_CAPACITY;
    use talpid_types::relay_flow::RelayTargetId;
    let (broker, root, credit) = broker();
    let mut config = config();
    let (remote, mut observations, _) = remote_controlled(&mut config, false).await;
    let pending = projected(&broker, &config);
    let capture = bind(&broker);
    let mut started = GotaTun::new(
        PlaintextSource::Managed(pending),
        Arc::new(NoopBypass),
        None,
        &config,
        None,
        String::new(),
    )
    .await
    .unwrap();
    // Real carrier ordinary output starts before connectivity/Up is evaluated.
    let early = packet(&config, false, 17, b"carrier-before-Up", false, false);
    capture.try_send(&early).unwrap();
    assert_eq!(
        observed(&mut observations).await,
        packet(&config, false, 17, b"carrier-before-Up", true, false)
    );
    assert_eq!(capture_bytes(&capture).await, application_reply(&early));
    started.shutdown().await;
    drop(started);
    let pending = projected(&broker, &config);
    capture
        .acknowledge_request(&broker.pending_request().unwrap())
        .unwrap();
    let client = GatedTunnel::new(pending, &config).await;
    let mut check = client.check().await;
    let (pending_return, return_waiting) = tokio::sync::oneshot::channel();
    *client.owner.return_pending.lock().unwrap() = Some(pending_return);
    client.gate.enabled.store(true, Ordering::Release);
    let held = packet(&config, false, 17, b"held-native-handoff", false, false);
    capture.try_send(&held).unwrap();
    client.gate.held_after(0).await;
    for index in 0..PACKET_CAPACITY {
        capture
            .try_send(&packet(
                &config,
                false,
                17,
                &index.to_be_bytes(),
                false,
                false,
            ))
            .unwrap();
    }
    let nonce = packet(
        &config,
        false,
        17,
        b"capacity-plus-one-terminal-nonce",
        false,
        false,
    );
    let mut selected = capture.ingress(RelayTargetId::MULLVAD, &nonce).unwrap();
    assert!(selected.send().now_or_never().is_none());
    local_progress(&capture.capability().unwrap());
    client.gate.enabled.store(false, Ordering::Release);
    client.gate.permits.add_permits(1);
    tokio::time::timeout(Duration::from_secs(2), selected.send())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        observed(&mut observations).await,
        packet(&config, false, 17, b"held-native-handoff", true, false)
    );
    // Hold the capture return consumer until its bounded bridge is saturated;
    // the already-owned extra return must survive without false send success.
    for index in 0..PACKET_CAPACITY {
        assert_eq!(
            observed(&mut observations).await,
            packet(&config, false, 17, &index.to_be_bytes(), true, false)
        );
    }
    assert_eq!(
        observed(&mut observations).await,
        packet(
            &config,
            false,
            17,
            b"capacity-plus-one-terminal-nonce",
            true,
            false
        )
    );
    tokio::time::timeout(Duration::from_secs(2), return_waiting)
        .await
        .expect("owned native return never waited for capacity")
        .unwrap();
    assert_eq!(capture_bytes(&capture).await, application_reply(&held));
    for index in 0..PACKET_CAPACITY {
        assert_eq!(
            capture_bytes(&capture).await,
            application_reply(&packet(
                &config,
                false,
                17,
                &index.to_be_bytes(),
                false,
                false
            ))
        );
    }
    assert_eq!(capture_bytes(&capture).await, application_reply(&nonce));
    let prior = client.owner.ledger.lock().unwrap().highest;
    assert!(check.establish_connectivity(&client).await.unwrap());
    private_done(&client.owner, prior).await;
    local_progress(&capture.capability().unwrap());
    drop(selected);
    client.shutdown().await;
    drop(check);
    capture.retire();
    drop(capture);
    assert_eq!(credit.used(), 0);
    remote.stop().await;
    // Root retains the fixed regions while broker lives; all packet bytes refund.
    drop(broker);
    drop(credit);
    assert_eq!(root.used(), 0);
}

#[cfg(unix)]
fn local_progress(session: &talpid_types::relay_flow::RelayCapture) {
    let sink = session.sink().unwrap();
    let (fd, consumer) = std::os::unix::net::UnixDatagram::pair().unwrap();
    session
        .with_sink(&sink, || fd.send(b"independent-local"))
        .unwrap()
        .unwrap();
    consumer
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut bytes = [0; 32];
    let count = consumer.recv(&mut bytes).unwrap();
    assert_eq!(&bytes[..count], b"independent-local");
}
struct RefusableApplication {
    inner: BufferBudget,
    exhausted: Arc<AtomicBool>,
    refused: Arc<tokio::sync::Notify>,
}
impl RelayBufferAllocator for RefusableApplication {
    fn try_reserve(&self, bytes: usize) -> Result<Arc<dyn RelayBufferReservation>, RelayFlowError> {
        if self.exhausted.load(Ordering::Acquire) {
            self.refused.notify_one();
            return Err(RelayFlowError::Full);
        }
        self.inner.try_reserve(bytes)
    }
}
fn refusable_broker() -> (
    AttachmentBroker,
    BufferBudget,
    Arc<AtomicBool>,
    Arc<tokio::sync::Notify>,
) {
    let root = BufferBudget::new(64 * 1024 * 1024);
    let application = root.reserve(22 * 1024 * 1024).unwrap().region().unwrap();
    let control = root.reserve(8 * 1024 * 1024).unwrap().region().unwrap();
    let capture = root.reserve(2 * 1024 * 1024).unwrap().region().unwrap();
    let exhausted = Arc::new(AtomicBool::new(false));
    let refused = Arc::new(tokio::sync::Notify::new());
    let broker = AttachmentBroker::new(
        Arc::new(RefusableApplication {
            inner: application,
            exhausted: exhausted.clone(),
            refused: refused.clone(),
        }),
        Arc::new(capture),
        Arc::new(control.clone()),
    )
    .unwrap();
    broker.set_mode(AttachmentMode::ManagedRequired).unwrap();
    (broker, control, exhausted, refused)
}

#[cfg(unix)]
#[tokio::test]
async fn ordinary_and_fresh_private_probes_progress_with_continuously_ready_packets() {
    let (broker, _root, credit) = broker();
    let mut config = config();
    let (remote, mut observations, input) = remote_controlled(&mut config, false).await;
    let source = projected(&broker, &config);
    let capture = bind(&broker);
    let client = GatedTunnel::new(source, &config).await;
    let mut check = client.check().await;
    client.gate.enabled.store(true, Ordering::Release);
    // Separate packet arrivals, not a removed splitter's emission backlog.
    for nonce in 0..40 {
        capture.try_send(&oversize(&config, false, nonce)).unwrap();
    }
    let mut held = client.gate.held_after(0).await;
    inject(&input, &oversize(&config, true, 0x82)).await;
    let returned = capture_bytes(&capture).await;
    assert_eq!(returned, application_reply(&oversize(&config, false, 0x82)));
    let previous = client.owner.ledger.lock().unwrap().highest;
    assert!(check.establish_connectivity(&client).await.unwrap());
    for _ in 0..8 {
        client.gate.permits.add_permits(1);
        held = client.gate.held_after(held).await;
    }
    for nonce in 0..7 {
        let received = observed(&mut observations).await;
        assert_eq!(received, application_reply(&oversize(&config, true, nonce)));
    }
    private_done(&client.owner, previous).await;
    local_progress(&capture.capability().unwrap());
    client.shutdown().await;
    drop(check);
    assert_eq!(credit.used(), 0);
    remote.stop().await;
}

#[cfg(unix)]
#[tokio::test]
async fn ordinary_owned_packets_preserve_blocked_writes_retirement_and_refunds() {
    let (broker, credit, exhausted, refused_allocation) = refusable_broker();
    let application = broker.application_buffers();
    let baseline = available(application.as_ref());
    let mut config = config();
    let (remote, mut observations, input) = remote_controlled(&mut config, false).await;
    let source = projected(&broker, &config);
    let capture = bind(&broker);
    let session = capture.capability().unwrap();
    let sink = session.sink().unwrap();
    let client = GatedTunnel::new(source, &config).await;
    let mut check = client.check().await;
    let app = oversize(&config, false, 0x92);
    capture.try_send(&app).unwrap();
    assert_eq!(
        observed(&mut observations).await,
        application_reply(&oversize(&config, true, 0x92))
    );
    let mut blocked = tokio::time::timeout(Duration::from_secs(2), capture.reply())
        .await
        .unwrap()
        .unwrap();
    let before = available(application.as_ref());
    let expected = application_reply(&app);
    for _ in 0..2 {
        assert!(matches!(
            blocked.write_to(&sink, |bytes| {
                assert_eq!(bytes, expected);
                Err(io::ErrorKind::WouldBlock.into())
            }),
            RelayWriteOutcome::Retry
        ));
        assert_eq!(
            available(application.as_ref()),
            before,
            "WouldBlock released owned charge"
        );
    }
    let target = client
        .owner
        .path
        .lock()
        .unwrap()
        .process(&app, Direction::Outbound)
        .unwrap();
    // Preserve the real ordinary queue bound. The blocked writer remains charged
    // outside this queue, just as in normal descriptor backpressure.
    for _ in 0..talpid_tunnel::packet_attachment::PACKET_CAPACITY {
        client.owner.ordinary_send.try_send(&expected).unwrap();
    }
    let queued = available(application.as_ref());
    assert_eq!(
        client.owner.ordinary_send.try_send(&expected),
        Err(talpid_tunnel::packet_attachment::AttachmentError::Full)
    );
    assert_eq!(available(application.as_ref()), queued);
    let exhaustion = application
        .try_reserve(available(application.as_ref()))
        .unwrap();
    exhausted.store(true, Ordering::Release);
    let refused = client
        .owner
        .path
        .lock()
        .unwrap()
        .summary()
        .refused(TranslationError::Full);
    inject(&input, &oversize(&config, true, 0x93)).await;
    tokio::time::timeout(Duration::from_secs(2), refused_allocation.notified())
        .await
        .expect("ordinary allocation refusal not observed");
    assert!(
        client
            .owner
            .path
            .lock()
            .unwrap()
            .summary()
            .refused(TranslationError::Full)
            > refused
    );
    let previous = client.owner.ledger.lock().unwrap().highest;
    assert!(check.establish_connectivity(&client).await.unwrap());
    private_done(&client.owner, previous).await;
    local_progress(&session);
    exhausted.store(false, Ordering::Release);
    drop(exhaustion);
    client.shutdown().await;
    drop(check);
    assert_eq!(credit.used(), 0);
    remote.stop().await;

    let (remote, mut observations, _input) = remote_controlled(&mut config, false).await;
    let source = projected(&broker, &config);
    capture
        .acknowledge_request(&broker.pending_request().unwrap())
        .unwrap();
    let mut successor = GotaTun::new(
        PlaintextSource::Managed(source),
        Arc::new(NoopBypass),
        None,
        &config,
        None,
        String::new(),
    )
    .await
    .unwrap();
    let owner = successor.managed().unwrap();
    let (_cancel, receiver) = CancelToken::new();
    let mut check = Check::new_with_smoltcp(owner.pinger().unwrap(), 0, receiver);
    establish_and_observe(&mut check, &successor, &owner, async { Ok(()) })
        .await
        .unwrap();
    assert!(matches!(
        blocked.write_to(&sink, |_| panic!("old return entered successor")),
        RelayWriteOutcome::Stale
    ));
    assert!(matches!(
        talpid_netstack::raw_packet::handoff(target, application.as_ref(), |_| panic!(
            "old target entered successor"
        )),
        Err(RelayFlowError::Stale)
    ));
    let before = available(application.as_ref());
    drop(blocked);
    assert!(
        available(application.as_ref()) >= before + expected.len(),
        "old owned packet was not refunded"
    );
    let app = packet(&config, false, 17, b"fresh-after-retirement", false, false);
    capture.try_send(&app).unwrap();
    assert_eq!(
        observed(&mut observations).await,
        packet(&config, false, 17, b"fresh-after-retirement", true, false)
    );
    assert_eq!(capture_bytes(&capture).await, application_reply(&app));
    local_progress(&session);
    let large = oversize(&config, false, 0x95);
    capture.try_send(&large).unwrap();
    assert_eq!(
        observed(&mut observations).await,
        application_reply(&oversize(&config, true, 0x95))
    );
    assert_eq!(capture_bytes(&capture).await, application_reply(&large));
    successor.shutdown().await;
    drop((owner, check, successor));
    assert_eq!(credit.used(), 0);
    assert_eq!(available(application.as_ref()), baseline);
    remote.stop().await;
}
