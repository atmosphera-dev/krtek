//! Distinguish absent authority from a broken Java snapshot conversion.
use jnix::jni::{JNIEnv, objects::JObject};

pub(super) fn decode<T>(
    env: &JNIEnv<'_>,
    object: JObject<'_>,
    convert: impl FnOnce() -> T,
) -> Result<Option<T>, ()> {
    if object.is_null() {
        log::debug!("System DNS snapshot unavailable: no selected non-VPN network");
        return Ok(None);
    }
    // jnix's FromJava conversions panic on invalid field/method representations.
    // Preserve the fail-closed adapter result without losing the reactor worker.
    let converted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(convert));
    match converted {
        Ok(value) if !env.exception_check().unwrap_or(true) => Ok(Some(value)),
        _ => {
            log::warn!("System DNS snapshot conversion failed");
            Err(())
        }
    }
}
