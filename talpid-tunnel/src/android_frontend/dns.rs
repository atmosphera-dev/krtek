//! Injected selective consumer, owned and polled by the sole capture reactor.
use std::{future::Future, io, net::IpAddr, pin::Pin, sync::Arc};
use talpid_types::relay_flow::{
    RelayBufferAllocator, RelayCapture, RelayIngressOriginal, RelaySink,
};

pub type DnsFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// No descriptor access, second reader, route classifier or physical authority.
pub trait DnsReceiver: Send {
    fn set_partial(&mut self, _partial: bool) {}
    /// A cheap candidate test, before allocating the demand-bound Local arena.
    fn candidate(&self, bytes: &[u8], advertised: &[IpAddr]) -> bool;
    /// true consumes this packet; false retains its original normal IP path.
    fn ingest(
        &mut self,
        bytes: &[u8],
        advertised: &[IpAddr],
        capture: &RelayCapture,
        replies: Arc<dyn RelayBufferAllocator>,
        mtu: u16,
    ) -> bool;
    fn original(&mut self) -> Option<RelayIngressOriginal>;
    fn has_original(&self) -> bool;
    fn has_output(&self) -> bool;
    fn set_mtu(&mut self, mtu: u16) -> Result<(), talpid_lan_forwarder::Refused>;
    fn reset_inputs(&mut self);
    fn revalidate(&mut self);
    fn process(&mut self);
    fn wait(&mut self) -> DnsFuture<'_, ()>;
    /// This consumer owns its capture check. The callback checks observation/fd.
    fn write_output(
        &mut self,
        sink: &RelaySink,
        write: &mut dyn FnMut(&[u8]) -> io::Result<usize>,
    ) -> io::Result<bool>;
    fn close(&mut self) -> DnsFuture<'_, io::Result<()>>;
}
