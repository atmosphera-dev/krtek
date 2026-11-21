//! Test-only barrier, absent from normal JNI libraries.
use jnix::{
    FromJava, JnixEnv,
    jni::{
        JNIEnv,
        objects::{JObject, JString},
        sys::jstring,
    },
};

#[unsafe(no_mangle)]
pub extern "system" fn Java_net_mullvad_mullvadvpn_talpid_PublicDnsObserverTest_barrier(
    env: JNIEnv<'_>,
    _: JObject<'_>,
    expected: JString<'_>,
) -> jstring {
    let env = JnixEnv::from(env);
    let expected = String::from_java(&env, expected);
    match mullvad_daemon::public_dns_diagnostics::barrier(&expected) {
        Ok(identity) => env
            .new_string(identity)
            .expect("diagnostic identity")
            .into_inner(),
        Err(error) => {
            env.throw(error.to_string()).expect("diagnostic exception");
            std::ptr::null_mut()
        }
    }
}
