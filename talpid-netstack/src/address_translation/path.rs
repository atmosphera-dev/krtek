use super::*;

/// Translate one endpoint packet, retaining its exact attempt through the final
/// write. Transmit MTU is native carrier metadata, not a receive-side limit.
pub struct TargetPacketPath {
    mapper: AddressTranslator,
}

impl TargetPacketPath {
    pub fn new(
        config: TargetConfig,
        attempt: RelayAttempt,
        buffers: Arc<dyn RelayBufferAllocator>,
    ) -> Result<Self, TranslationError> {
        Ok(Self {
            mapper: AddressTranslator::new(config, attempt, buffers)?,
        })
    }
    pub fn config(&self) -> TargetConfig {
        self.mapper.config()
    }
    pub fn summary(&self) -> &TranslationSummary {
        self.mapper.summary()
    }
    pub fn backend_refused(&mut self) {
        self.mapper.backend_refused();
    }
    pub fn refused(&mut self, reason: TranslationError) {
        self.mapper.summary.refuse(reason);
    }
    pub fn process(
        &mut self,
        bytes: &[u8],
        direction: Direction,
    ) -> Result<RelayPacket, TranslationError> {
        self.mapper.translate(bytes, direction)
    }
}
