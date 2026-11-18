//! Funded Local IP completion and UDP output through the pinned native engine.
//! Scripted engines are fixtures only, never a production fallback.

pub(crate) mod contract;
pub(crate) mod ffi;

pub(crate) mod capture;
pub(crate) mod native;

#[cfg(test)]
mod contract_tests;

#[cfg(test)]
mod capture_tests;

#[cfg(test)]
mod native_tests;
