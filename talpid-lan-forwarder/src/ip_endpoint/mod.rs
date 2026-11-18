//! Shared Local IP contract, not selected by production forwarding until the
//! real native wrapper lands. No fixture engine is a production fallback.

pub(crate) mod contract;
pub(crate) mod ffi;

#[cfg(test)]
mod contract_tests;
