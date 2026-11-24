//! Local receiver allocation is demand-bound, independent of capture storage.
use super::*;
use talpid_lan_forwarder::Refused;
use talpid_types::relay_flow::RelayIngressOriginal;

pub struct LocalReceiver<A: LocalAuthority> {
    receiver: Option<Forwarder<A>>,
    factory: Box<dyn FnMut(usize) -> Result<Forwarder<A>, Refused> + Send>,
    mtu: usize,
    dns: Option<Box<dyn DnsReceiver>>,
    dns_first: bool,
    dns_servers: Vec<std::net::IpAddr>,
}

impl<A: LocalAuthority> LocalReceiver<A> {
    pub fn new(
        factory: impl FnMut(usize) -> Result<Forwarder<A>, Refused> + Send + 'static,
    ) -> Self {
        Self {
            receiver: None,
            factory: Box::new(factory),
            mtu: 1280,
            dns: None,
            dns_first: false,
            dns_servers: Vec::new(),
        }
    }
    pub fn with_dns(mut self, dns: impl DnsReceiver + 'static) -> Self {
        self.dns = Some(Box::new(dns));
        self
    }

    fn ensure(&mut self) -> Result<&mut Forwarder<A>, Refused> {
        if self.receiver.is_none() {
            self.receiver = Some((self.factory)(self.mtu)?);
        }
        Ok(self.receiver.as_mut().expect("Local demand"))
    }
}
impl<A: LocalAuthority> From<Forwarder<A>> for LocalReceiver<A> {
    fn from(receiver: Forwarder<A>) -> Self {
        Self {
            receiver: Some(receiver),
            factory: Box::new(|_| Err(Refused::Full)),
            mtu: 1280,
            dns: None,
            dns_first: false,
            dns_servers: Vec::new(),
        }
    }
}

pub(super) trait Receiver<A: LocalAuthority>: Send {
    fn receiver(&mut self) -> Option<&mut Forwarder<A>>;
    fn has_output(&self) -> bool;
    fn set_mtu(&mut self, mtu: usize) -> Result<(), Refused>;
    fn ingest(&mut self, bytes: &[u8]);
    fn intercept(
        &mut self,
        _bytes: &[u8],
        _advertised: &[std::net::IpAddr],
        _capture: &RelayCapture,
        _mtu: u16,
    ) -> bool {
        false
    }
    fn original(&mut self) -> Option<RelayIngressOriginal> {
        None
    }
    fn has_original(&self) -> bool {
        false
    }
    fn set_dns_servers(&mut self, _advertised: &[std::net::IpAddr]) {}
    fn set_dns_partial(&mut self, _partial: bool) {}
    fn write_output(
        &mut self,
        session: Option<(&RelayCapture, &RelaySink)>,
        mut write: impl FnMut(&[u8]) -> io::Result<usize>,
    ) -> io::Result<bool> {
        match self.receiver() {
            Some(receiver) => receiver.write_output(|bytes| match session {
                Some((capture, sink)) => capture
                    .with_sink(sink, || write(bytes))
                    .map_err(|_| io::Error::other("Capture session retired"))?,
                None => write(bytes),
            }),
            None => Ok(false),
        }
    }
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
    fn close_all(&mut self) -> impl std::future::Future<Output = io::Result<()>> + Send {
        async move {
            if let Some(receiver) = self.receiver() {
                receiver.close_all().await;
            }
            Ok(())
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
            || self.dns.as_ref().is_some_and(|dns| dns.has_output())
    }
    fn set_mtu(&mut self, mtu: usize) -> Result<(), Refused> {
        talpid_lan_forwarder::validate_mtu(mtu)?;
        self.mtu = mtu;
        if let Some(dns) = &mut self.dns {
            dns.set_mtu(mtu as u16)?;
        }
        match self.receiver.as_mut() {
            Some(receiver) => receiver.set_mtu(mtu),
            None => Ok(()),
        }
    }
    fn ingest(&mut self, bytes: &[u8]) {
        if let Ok(receiver) = self.ensure() {
            receiver.ingest(bytes);
        }
    }
    fn intercept(
        &mut self,
        bytes: &[u8],
        advertised: &[std::net::IpAddr],
        capture: &RelayCapture,
        mtu: u16,
    ) -> bool {
        if !self
            .dns
            .as_ref()
            .is_some_and(|dns| dns.candidate(bytes, advertised))
        {
            return false;
        }
        let Ok(receiver) = self.ensure() else {
            return true;
        };
        let replies = receiver.reply_buffers();
        self.dns
            .as_mut()
            .expect("DNS candidate")
            .ingest(bytes, advertised, capture, replies, mtu)
    }
    fn original(&mut self) -> Option<RelayIngressOriginal> {
        self.dns.as_mut().and_then(|dns| dns.original())
    }
    fn has_original(&self) -> bool {
        self.dns.as_ref().is_some_and(|dns| dns.has_original())
    }
    fn set_dns_servers(&mut self, advertised: &[std::net::IpAddr]) {
        if self.dns_servers != advertised {
            if let Some(dns) = &mut self.dns {
                dns.reset_inputs();
            }
            self.dns_servers = advertised.to_vec();
        }
    }
    fn set_dns_partial(&mut self, partial: bool) {
        if let Some(dns) = &mut self.dns {
            dns.set_partial(partial);
        }
    }
    fn revalidate(&mut self) {
        if let Some(receiver) = &mut self.receiver {
            receiver.revalidate();
        }
        if let Some(dns) = &mut self.dns {
            dns.revalidate();
        }
    }
    fn process(&mut self) {
        if let Some(receiver) = &mut self.receiver {
            receiver.process();
        }
        if let Some(dns) = &mut self.dns {
            dns.process();
        }
    }
    async fn wait(&mut self) {
        tokio::select! {
            _ = async { match &mut self.receiver { Some(r) => r.wait().await, None => std::future::pending().await } } => {},
            _ = async { match &mut self.dns { Some(dns) => dns.wait().await, None => std::future::pending().await } } => {},
        }
    }
    async fn close_all(&mut self) -> io::Result<()> {
        if let Some(receiver) = &mut self.receiver {
            receiver.close_all().await;
        }
        if let Some(dns) = &mut self.dns {
            dns.close().await?;
        }
        Ok(())
    }
    fn write_output(
        &mut self,
        session: Option<(&RelayCapture, &RelaySink)>,
        mut write: impl FnMut(&[u8]) -> io::Result<usize>,
    ) -> io::Result<bool> {
        let mut written = false;
        for dns_first in if self.dns_first {
            [true, false]
        } else {
            [false, true]
        } {
            let progress = if dns_first {
                match (&mut self.dns, session) {
                    (Some(dns), Some((_, sink))) => dns.write_output(sink, &mut write)?,
                    _ => false,
                }
            } else {
                match &mut self.receiver {
                    Some(receiver) => receiver.write_output(|bytes| match session {
                        Some((capture, sink)) => capture
                            .with_sink(sink, || write(bytes))
                            .map_err(|_| io::Error::other("Capture session retired"))?,
                        None => write(bytes),
                    })?,
                    None => false,
                }
            };
            if progress {
                self.dns_first = !dns_first;
                written = true;
            }
        }
        Ok(written)
    }
}
