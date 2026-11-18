//! Exact call/response script, not an IP parser or fragmentation oracle.

use super::*;
use std::collections::VecDeque;

#[derive(Debug)]
pub struct Completion {
    pub scope: ReceiveScopeId,
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: Transport,
    pub segment: Vec<u8>,
}

#[derive(Debug)]
pub enum Step {
    Ingest {
        scope: ReceiveScopeId,
        ip: Vec<u8>,
        completions: Vec<Completion>,
        result: Result<Ingress, IpError>,
    },
    Reply {
        tuple: ReplyTuple,
        payload: Vec<u8>,
        packets: Vec<Vec<u8>>,
        result: Result<(), IpError>,
    },
    SetMtu(u16, Result<(), IpError>),
    PollTime(MonotonicMillis, Result<(), IpError>),
    Close,
}

pub struct ScriptedEngine {
    steps: VecDeque<Step>,
    closed: bool,
    pub timeout_ms: Option<u32>,
    pub references: Vec<(ReceiveScopeId, usize)>,
}

impl ScriptedEngine {
    pub fn new(steps: impl IntoIterator<Item = Step>) -> Self {
        Self {
            steps: steps.into_iter().collect(),
            closed: false,
            timeout_ms: None,
            references: Vec::new(),
        }
    }

    pub fn assert_finished(&self) {
        assert!(
            self.steps.is_empty(),
            "unconsumed engine steps: {:?}",
            self.steps
        );
    }

    fn next(&mut self) -> Result<Step, IpError> {
        if self.closed {
            return Err(IpError::Stale);
        }
        Ok(self.steps.pop_front().expect("unscripted engine call"))
    }
}

impl LocalIpEngine for ScriptedEngine {
    fn ingest(
        &mut self,
        scope: ReceiveScopeId,
        ip: &[u8],
        completed: &mut dyn FnMut(CompleteTransport<'_>),
    ) -> Result<Ingress, IpError> {
        let Step::Ingest {
            scope: expected,
            ip: bytes,
            completions,
            result,
        } = self.next()?
        else {
            panic!("expected an ingest step");
        };
        assert_eq!(scope, expected);
        assert_eq!(ip, bytes);
        for item in completions {
            completed(CompleteTransport {
                scope: item.scope,
                source: item.source,
                destination: item.destination,
                protocol: item.protocol,
                segment: &item.segment,
            });
        }
        result
    }

    fn reply(
        &mut self,
        tuple: ReplyTuple,
        payload: &[u8],
        output: &mut dyn FnMut(&[u8]),
    ) -> Result<(), IpError> {
        let Step::Reply {
            tuple: expected,
            payload: bytes,
            packets,
            result,
        } = self.next()?
        else {
            panic!("expected a reply step");
        };
        assert_eq!(tuple, expected);
        assert_eq!(payload, bytes);
        for packet in packets {
            output(&packet);
        }
        result
    }

    fn set_mtu(&mut self, mtu: u16) -> Result<(), IpError> {
        let Step::SetMtu(expected, result) = self.next()? else {
            panic!("expected an MTU step");
        };
        assert_eq!(mtu, expected);
        result
    }

    fn poll_time(&mut self, now: MonotonicMillis) -> Result<(), IpError> {
        let Step::PollTime(expected, result) = self.next()? else {
            panic!("expected a clock step");
        };
        assert_eq!(now, expected);
        result
    }

    fn next_timeout_ms(&self) -> Option<u32> {
        self.timeout_ms
    }

    fn scope_refs(&self, scope: ReceiveScopeId) -> usize {
        self.references
            .iter()
            .find(|(id, _)| *id == scope)
            .map_or(0, |(_, count)| *count)
    }

    fn close(&mut self) {
        if self.closed {
            return;
        }
        assert!(
            matches!(self.next(), Ok(Step::Close)),
            "expected a close step"
        );
        self.closed = true;
    }
}
