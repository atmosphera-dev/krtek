//! Production managed entry, also compiled against the platform boundary in Linux tests.
use super::*;
use talpid_lan_forwarder::Forwarder;
use talpid_tunnel::android_frontend::{
    FrontendOwner, FrontendPlatform, FrontendState, LocalReceiver,
};

pub struct PlatformFactory(pub Arc<dyn FrontendPlatform>);
pub struct PlatformOwner {
    owner: FrontendOwner,
    authority: Arc<DeliveryAuthority>,
    receiver: watch::Receiver<FrontendState>,
    open: bool,
    home: Arc<dyn crate::split_dns::home_path::HomeDnsPath>,
}
impl FrontendFactory for PlatformFactory {
    type Owner = PlatformOwner;
    fn supported(&self) -> bool {
        true
    }
    fn partial_dns(&self) -> Vec<IpAddr> {
        self.0
            .system_dns()
            .map_or_else(Vec::new, |snapshot| snapshot.dns_servers)
    }
    fn start(
        &self,
        config: DeliveryConfig,
        authority: Arc<DeliveryAuthority>,
        buffers: Arc<dyn RelayBufferAllocator>,
        broker: AttachmentBroker,
    ) -> io::Result<PlatformOwner> {
        let updates = authority.subscribe();
        let classifier = authority.clone();
        let receiver_authority = authority.clone();
        let home = crate::split_dns::local_home_path(authority.clone(), buffers.clone());
        let dns = crate::split_dns::capture::CaptureDns::new(
            authority.clone(),
            buffers.clone(),
            home.clone(),
        )
        .with_system(self.0.clone());
        let forwarder = LocalReceiver::new(move |mtu| {
            log::debug!("local-receiver-start capture_mtu={mtu}");
            Forwarder::with_mtu(receiver_authority.clone(), buffers.clone(), mtu)
        })
        .with_dns(dns);
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
            home,
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
        self.owner.stop().await?;
        // Keep and retry the SAME joined Home close after a failed actor join.
        self.home.close().await
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
