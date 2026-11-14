use super::*;
use crate::packet_sizing::{self, Emission, Feedback, FeedbackQueue, FeedbackSide};
use std::time::Instant;

pub enum TranslationOutcome {
    Packets(Emission),
    FeedbackQueued(FeedbackSide),
}

/// The production boundary: validate this packet, translate, size, then retain
/// packets/feedback with this exact attempt through the consumer's final write.
pub struct TargetPacketPath {
    mapper: AddressTranslator,
    feedback: FeedbackQueue,
}

impl TargetPacketPath {
    pub fn new(
        config: TargetConfig,
        attempt: RelayAttempt,
        buffers: Arc<dyn RelayBufferAllocator>,
    ) -> Result<Self, TranslationError> {
        let mapper = AddressTranslator::new(config, attempt, buffers.clone())?;
        let feedback = FeedbackQueue::new(buffers.as_ref())?;
        Ok(Self { mapper, feedback })
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
    pub fn take_feedback_for(&mut self, side: FeedbackSide) -> Option<Feedback> {
        if !self.mapper.attempt.current() {
            self.feedback.clear();
            return None;
        }
        self.feedback.pop_side(side)
    }
    pub fn take_feedback(&mut self) -> Option<Feedback> {
        if !self.mapper.attempt.current() {
            self.feedback.clear();
            return None;
        }
        self.feedback.pop()
    }
    pub fn deadline(&self) -> Option<Instant> {
        self.feedback.deadline()
    }
    pub fn maintain(&mut self, now: Instant) {
        if !self.mapper.attempt.current() {
            self.feedback.clear();
        } else {
            self.feedback.maintain(now);
        }
    }
    pub fn process(
        &mut self,
        bytes: &[u8],
        direction: Direction,
        sink_mtu: u16,
        now: Instant,
    ) -> Result<TranslationOutcome, TranslationError> {
        let mut result = self.process_inner(bytes, direction, sink_mtu, now);
        if !self.mapper.attempt.current() {
            result = Err(TranslationError::Stale);
        }
        match &result {
            Ok(TranslationOutcome::Packets(_)) => {
                self.mapper.summary.translated = self.mapper.summary.translated.saturating_add(1)
            }
            Err(reason) => self.mapper.summary.refuse(*reason),
            _ => (),
        }
        result
    }
    fn process_inner(
        &mut self,
        bytes: &[u8],
        direction: Direction,
        sink_mtu: u16,
        now: Instant,
    ) -> Result<TranslationOutcome, TranslationError> {
        self.maintain(now);
        if !self.mapper.attempt.current() {
            return Err(TranslationError::Stale);
        }
        if sink_mtu < 68 {
            return Err(TranslationError::Malformed);
        }
        let header = self.mapper.validate_packet(bytes, direction)?;
        let output_mtu = if direction == Direction::Outbound {
            self.mapper.config.mtu
        } else {
            sink_mtu
        };
        // Decide impossibility from the validated input before spending ordinary
        // data credit. Reserved feedback must progress when data credit is full.
        let needs_feedback = packet_sizing::needs_feedback(bytes, &header, output_mtu);
        let emitted = if needs_feedback {
            Err(TranslationError::PacketTooBig)
        } else {
            let translated = self.mapper.translate_buffer(bytes, direction)?;
            packet_sizing::emit(
                translated,
                &header,
                output_mtu,
                &self.mapper.attempt,
                self.mapper.buffers.as_ref(),
            )
        };
        match emitted {
            Ok(packets) => Ok(TranslationOutcome::Packets(packets)),
            Err(TranslationError::PacketTooBig) => {
                let sources = if direction == Direction::Outbound {
                    self.mapper.config.fixed
                } else {
                    self.mapper.config.assigned
                };
                let source = if header.ipv4 && direction == Direction::Outbound {
                    // The fixed interface address is local to the receiving
                    // kernel. IPv4 rejects such incoming sources by default.
                    // Return the error from the invoking remote endpoint instead.
                    let IpAddr::V4(remote) = header.destination else {
                        return Err(TranslationError::Family);
                    };
                    if Some(remote) == self.mapper.config.fixed.ipv4
                        || remote.is_unspecified()
                        || remote.is_loopback()
                        || remote.is_multicast()
                        || remote.is_broadcast()
                    {
                        return Err(TranslationError::Suppressed);
                    }
                    Some(remote.into())
                } else if header.ipv4 {
                    sources.ipv4.map(IpAddr::V4)
                } else {
                    sources.ipv6.map(IpAddr::V6)
                }
                .ok_or(TranslationError::Family)?;
                let side = if direction == Direction::Outbound {
                    FeedbackSide::App
                } else {
                    FeedbackSide::Target
                };
                let return_mtu = if side == FeedbackSide::App {
                    sink_mtu
                } else {
                    self.mapper.config.mtu
                };
                self.feedback.generate(
                    bytes,
                    &header,
                    packet_sizing::FeedbackRoute {
                        source,
                        mtu: output_mtu,
                        return_mtu,
                        side,
                    },
                    &self.mapper.attempt,
                    now,
                )?;
                Ok(TranslationOutcome::FeedbackQueued(side))
            }
            Err(error) => Err(error),
        }
    }
}
