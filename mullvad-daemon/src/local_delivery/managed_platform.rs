//! Production managed entry, also compiled against the platform boundary in Linux tests.
use super::*;
use talpid_lan_forwarder::Forwarder;
use talpid_tunnel::android_frontend::{FrontendOwner, FrontendPlatform, FrontendState};

pub struct PlatformFactory(pub Arc<dyn FrontendPlatform>);
pub struct PlatformOwner {
    owner: FrontendOwner,
    authority: Arc<DeliveryAuthority>,
    receiver: watch::Receiver<FrontendState>,
    open: bool,
}
impl FrontendFactory for PlatformFactory {
    type Owner = PlatformOwner;
    fn supported(&self) -> bool {
        true
    }
    fn start(
        &self,
        config: DeliveryConfig,
        authority: Arc<DeliveryAuthority>,
        buffers: Arc<dyn RelayBufferAllocator>,
        broker: AttachmentBroker,
    ) -> io::Result<PlatformOwner> {
        let updates = authority.subscribe();
        let mtu = config.mtu();
        let classifier = authority.clone();
        log::debug!(
            "local-receiver-start capture_mtu={mtu} packet_ceiling={}",
            talpid_lan_forwarder::packet::MAX_PACKET_SIZE
        );
        let forwarder =
            Forwarder::with_mtu(authority.clone(), buffers, usize::from(mtu)).map_err(|error| {
                match error {
                    Refused::UnsupportedMtu => io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("Unsupported Local capture MTU {mtu}"),
                    ),
                    _ => io::Error::other("Local storage budget full"),
                }
            })?;
        let owner = FrontendOwner::start(
            self.0.clone(),
            config.into_frontend(classifier),
            forwarder,
            updates,
            broker,
        )?;
        let receiver = owner.state();
        Ok(PlatformOwner {
            owner,
            authority,
            receiver,
            open: true,
        })
    }
}
impl DeliveryOwner for PlatformOwner {
    fn handover(&mut self, config: DeliveryConfig) -> io::Result<()> {
        self.owner
            .handover(config.into_frontend(self.authority.clone()))
    }
    fn retry_handover_release(&mut self) -> io::Result<()> {
        self.owner.retry_handover_release()
    }
    async fn ready(&mut self) -> io::Result<()> {
        self.owner.ready().await
    }
    async fn stop(&mut self) -> io::Result<()> {
        self.owner.stop().await
    }
    fn retry_release(&mut self) -> io::Result<()> {
        self.owner.retry_release()
    }
    fn state(&self) -> OwnerState {
        match *self.receiver.borrow() {
            FrontendState::Running => OwnerState::Running,
            FrontendState::Stopped => OwnerState::Stopped,
            FrontendState::Failed => OwnerState::Failed,
        }
    }
    fn release_failed(&self) -> bool {
        self.owner.release_failed()
    }
    async fn changed(&mut self) {
        if self.open {
            self.open = self.receiver.changed().await.is_ok();
        } else {
            std::future::pending().await
        }
    }
}
