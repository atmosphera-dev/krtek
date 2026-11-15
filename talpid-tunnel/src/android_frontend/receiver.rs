//! Local receiver allocation is demand-bound, independent of capture storage.
use super::*;
use talpid_lan_forwarder::Refused;

pub struct LocalReceiver<A: LocalAuthority> {
    receiver: Option<Forwarder<A>>,
    factory: Box<dyn FnMut(usize) -> Result<Forwarder<A>, Refused> + Send>,
    mtu: usize,
}

impl<A: LocalAuthority> LocalReceiver<A> {
    pub fn new(
        factory: impl FnMut(usize) -> Result<Forwarder<A>, Refused> + Send + 'static,
    ) -> Self {
        Self {
            receiver: None,
            factory: Box::new(factory),
            mtu: 1280,
        }
    }
}
impl<A: LocalAuthority> From<Forwarder<A>> for LocalReceiver<A> {
    fn from(receiver: Forwarder<A>) -> Self {
        Self {
            receiver: Some(receiver),
            factory: Box::new(|_| Err(Refused::Full)),
            mtu: 1280,
        }
    }
}

pub(super) trait Receiver<A: LocalAuthority>: Send {
    fn receiver(&mut self) -> Option<&mut Forwarder<A>>;
    fn has_output(&self) -> bool;
    fn set_mtu(&mut self, mtu: usize) -> Result<(), Refused>;
    fn ingest(&mut self, bytes: &[u8]);
    fn revalidate(&mut self) {
        if let Some(receiver) = self.receiver() {
            receiver.revalidate();
        }
    }
    fn process(&mut self) {
        if let Some(receiver) = self.receiver() {
            receiver.process();
        }
    }
    fn wait(&mut self) -> impl std::future::Future<Output = ()> + Send {
        async move {
            match self.receiver() {
                Some(receiver) => receiver.wait().await,
                None => std::future::pending().await,
            }
        }
    }
    fn close_all(&mut self) -> impl std::future::Future<Output = ()> + Send {
        async move {
            if let Some(receiver) = self.receiver() {
                receiver.close_all().await;
            }
        }
    }
}
impl<A: LocalAuthority> Receiver<A> for Forwarder<A> {
    fn receiver(&mut self) -> Option<&mut Forwarder<A>> {
        Some(self)
    }
    fn has_output(&self) -> bool {
        self.has_output()
    }
    fn set_mtu(&mut self, mtu: usize) -> Result<(), Refused> {
        self.set_mtu(mtu)
    }
    fn ingest(&mut self, bytes: &[u8]) {
        self.ingest(bytes);
    }
}
impl<A: LocalAuthority> Receiver<A> for LocalReceiver<A> {
    fn receiver(&mut self) -> Option<&mut Forwarder<A>> {
        self.receiver.as_mut()
    }
    fn has_output(&self) -> bool {
        self.receiver.as_ref().is_some_and(Forwarder::has_output)
    }
    fn set_mtu(&mut self, mtu: usize) -> Result<(), Refused> {
        talpid_lan_forwarder::validate_mtu(mtu)?;
        self.mtu = mtu;
        match self.receiver.as_mut() {
            Some(receiver) => receiver.set_mtu(mtu),
            None => Ok(()),
        }
    }
    fn ingest(&mut self, bytes: &[u8]) {
        if self.receiver.is_none() {
            match (self.factory)(self.mtu) {
                Ok(receiver) => self.receiver = Some(receiver),
                Err(error) => {
                    log::debug!("Local receiver construction refused: {error:?}");
                    return;
                }
            }
        }
        self.receiver.as_mut().expect("Local demand").ingest(bytes);
    }
}
