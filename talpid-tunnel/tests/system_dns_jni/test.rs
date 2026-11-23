//! Task-owned JVM proof of the exact production nullable/exception decode boundary.
#[path = "../../src/tun_provider/android/local_network/jni_call.rs"]
mod jni_call;
#[path = "../../src/tun_provider/android/local_network/system_dns.rs"]
mod system_dns;

use jnix::jni::{
    InitArgsBuilder, JNIVersion, JavaVM,
    objects::{JObject, JValue},
};
use std::sync::Mutex;

struct Diagnostics(Mutex<Vec<String>>);
static DIAGNOSTICS: Diagnostics = Diagnostics(Mutex::new(Vec::new()));

impl log::Log for Diagnostics {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }
    fn log(&self, record: &log::Record<'_>) {
        self.0.lock().unwrap().push(record.args().to_string());
    }
    fn flush(&self) {}
}

#[test]
fn null_and_failed_conversion_are_distinct_and_do_not_poison_the_attached_worker() {
    log::set_logger(&DIAGNOSTICS).unwrap();
    log::set_max_level(log::LevelFilter::Debug);
    let args = InitArgsBuilder::new()
        .version(JNIVersion::V8)
        .option("-Xcheck:jni")
        .build()
        .unwrap();
    let vm = JavaVM::new(args).unwrap();
    let env = vm.attach_current_thread_as_daemon().unwrap();
    let pointer = env.get_native_interface();
    assert_eq!(
        system_dns::decode::<i64>(&env, JObject::null(), || panic!("null must not convert")),
        Ok(None)
    );
    let object = env.auto_local(
        env.new_object("java/lang/Long", "(J)V", &[JValue::Long(7)])
            .unwrap(),
    );
    let bad = jni_call::handled(&env, "systemDnsSnapshot", || {
        system_dns::decode(&env, object.as_obj(), || {
            // jnix FromJava has the same fallible access/unwrap behavior on a bad representation.
            env.get_field(object.as_obj(), "token", "J")
                .unwrap()
                .j()
                .unwrap()
        })
    });
    assert!(bad.is_err());
    assert!(
        !env.exception_check().unwrap(),
        "conversion retained a Java exception"
    );
    let good = system_dns::decode(&env, object.as_obj(), || {
        env.call_method(object.as_obj(), "longValue", "()J", &[])
            .unwrap()
            .j()
            .unwrap()
    });
    assert_eq!(good, Ok(Some(7)));
    assert_eq!(env.get_native_interface(), pointer);
    let logs = DIAGNOSTICS.0.lock().unwrap();
    assert!(
        logs.iter()
            .any(|line| line.contains("System DNS snapshot unavailable"))
    );
    assert!(
        logs.iter()
            .any(|line| line.contains("System DNS snapshot conversion failed"))
    );
    assert!(logs.iter().any(|line| line.contains("NoSuchFieldError")));
}
