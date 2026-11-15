//! Result conversion never owns a raw fd. The service retains its descriptor
//! until the last primitive transfer, so getter/acknowledgement failures cannot
//! strand a detached descriptor or require adopting one twice.
use crate::tun_provider::{AndroidTunConfig, AppliedTun, ConfigurationError};
use jnix::jni::{
    JNIEnv,
    objects::{JObject, JString, JValue},
};
use std::net::IpAddr;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

pub(super) const TAKE: (&str, &str) = ("takeLocalFrontendDescriptor", "(J)I");

#[derive(Debug)]
pub(super) enum DecodeError {
    Jni(jnix::jni::errors::Error),
    InvalidResult,
}

impl From<jnix::jni::errors::Error> for DecodeError {
    fn from(error: jnix::jni::errors::Error) -> Self {
        Self::Jni(error)
    }
}

#[derive(Debug)]
pub(super) enum OpenResult {
    Descriptor(DecodedDescriptor),
    EstablishError,
    OtherLegacyAlwaysOnVpn,
    OtherAlwaysOnApp(String),
    NotPrepared,
}

#[derive(Debug)]
pub(super) struct DecodedDescriptor {
    pub raw: RawFd,
    pub profile: Option<AndroidTunConfig>,
    pub cause: Option<ConfigurationError>,
}

fn list<T>(
    env: &JNIEnv<'_>,
    object: JObject<'_>,
    method: &str,
    decode: impl Fn(&JNIEnv<'_>, JObject<'_>) -> Result<T, DecodeError>,
) -> Result<Vec<T>, DecodeError> {
    let values = env
        .call_method(object, method, "()Ljava/util/ArrayList;", &[])?
        .l()?;
    let values = env.auto_local(values);
    let count = env.call_method(values.as_obj(), "size", "()I", &[])?.i()?;
    if count < 0 {
        return Err(DecodeError::InvalidResult);
    }
    let mut out = Vec::new();
    for index in 0..count {
        let value = env
            .call_method(
                values.as_obj(),
                "get",
                "(I)Ljava/lang/Object;",
                &[JValue::Int(index)],
            )?
            .l()?;
        let value = env.auto_local(value);
        out.push(decode(env, value.as_obj())?);
    }
    Ok(out)
}

fn ip(env: &JNIEnv<'_>, object: JObject<'_>) -> Result<IpAddr, DecodeError> {
    let bytes = env.call_method(object, "getAddress", "()[B", &[])?.l()?;
    let bytes = env.auto_local(bytes);
    let bytes = env.convert_byte_array(bytes.as_obj().into_inner())?;
    match bytes.len() {
        4 => Ok(std::net::Ipv4Addr::from(
            <[u8; 4]>::try_from(bytes).map_err(|_| DecodeError::InvalidResult)?,
        )
        .into()),
        16 => Ok(std::net::Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes).map_err(|_| DecodeError::InvalidResult)?,
        )
        .into()),
        _ => Err(DecodeError::InvalidResult),
    }
}

fn network(env: &JNIEnv<'_>, object: JObject<'_>) -> Result<ipnetwork::IpNetwork, DecodeError> {
    let address = env
        .call_method(object, "getAddress", "()Ljava/net/InetAddress;", &[])?
        .l()?;
    let address = env.auto_local(address);
    let address = ip(env, address.as_obj())?;
    let prefix = env
        .call_method(object, "getPrefixLength", "()S", &[])?
        .s()?;
    ipnetwork::IpNetwork::new(
        address,
        u8::try_from(prefix).map_err(|_| DecodeError::InvalidResult)?,
    )
    .map_err(|_| DecodeError::InvalidResult)
}

fn string(env: &JNIEnv<'_>, object: JObject<'_>) -> Result<String, DecodeError> {
    Ok(String::from(env.get_string(JString::from(object))?))
}

fn profile(env: &JNIEnv<'_>, result: JObject<'_>) -> Result<Option<AndroidTunConfig>, DecodeError> {
    let object = env
        .call_method(
            result,
            "getAppliedConfig",
            "()Lnet/mullvad/talpid/model/TunConfig;",
            &[],
        )?
        .l()?;
    let object = env.auto_local(object);
    let object = object.as_obj();
    if object.is_null() {
        return Ok(None);
    }
    Ok(Some(AndroidTunConfig {
        addresses: list(env, object, "getAddresses", ip)?,
        dns_servers: list(env, object, "getDnsServers", ip)?,
        routes: list(env, object, "getRoutes", network)?,
        excluded_packages: list(env, object, "getExcludedPackages", string)?,
        mtu: u16::try_from(env.call_method(object, "getMtu", "()I", &[])?.i()?)
            .map_err(|_| DecodeError::InvalidResult)?,
    }))
}

// Unlike FromJava's derived getters, every conversion here is fallible. No
// detached fd is exposed until all discriminants and metadata have been read.
pub(super) fn decode(env: &JNIEnv<'_>, result: JObject<'_>) -> Result<OpenResult, DecodeError> {
    if result.is_null() {
        return Err(DecodeError::InvalidResult);
    }
    let class = env.auto_local(JObject::from(env.get_object_class(result)?));
    let name = env
        .call_method(class.as_obj(), "getName", "()Ljava/lang/String;", &[])?
        .l()?;
    let name = env.auto_local(name);
    let name = String::from(env.get_string(JString::from(name.as_obj()))?);
    Ok(
        match name.strip_prefix("net.mullvad.talpid.model.CreateTunResult$") {
            Some(kind @ ("Success" | "InvalidDnsServers" | "InvalidIpv6Config")) => {
                let cause = match kind {
                    "InvalidDnsServers" => Some(ConfigurationError::InvalidDnsServers(list(
                        env,
                        result,
                        "getAddresses",
                        ip,
                    )?)),
                    "InvalidIpv6Config" => Some(ConfigurationError::InvalidIpv6Config {
                        addresses: list(env, result, "getAddresses", ip)?,
                        routes: list(env, result, "getRoutes", network)?,
                        dns_servers: list(env, result, "getDnsServers", ip)?,
                    }),
                    _ => None,
                };
                let profile = profile(env, result)?;
                let fd = env.call_method(result, "getTunFd", "()I", &[])?.i()?;
                if fd < 0 {
                    return Err(DecodeError::InvalidResult);
                }
                OpenResult::Descriptor(DecodedDescriptor {
                    raw: fd,
                    profile,
                    cause,
                })
            }
            Some("EstablishError") => OpenResult::EstablishError,
            Some("OtherLegacyAlwaysOnVpn") => OpenResult::OtherLegacyAlwaysOnVpn,
            Some("OtherAlwaysOnApp") => {
                let name = env
                    .call_method(result, "getAppName", "()Ljava/lang/String;", &[])?
                    .l()?;
                let name = env.auto_local(name);
                OpenResult::OtherAlwaysOnApp(String::from(
                    env.get_string(JString::from(name.as_obj()))?,
                ))
            }
            Some("NotPrepared") => OpenResult::NotPrepared,
            _ => return Err(DecodeError::InvalidResult),
        },
    )
}

pub(super) fn take(
    env: &JNIEnv<'_>,
    service: JObject<'_>,
    generation: i64,
    expected: RawFd,
) -> Result<OwnedFd, DecodeError> {
    let raw = env
        .call_method(service, TAKE.0, TAKE.1, &[JValue::Long(generation)])?
        .i()?;
    if raw < 0 {
        return Err(DecodeError::InvalidResult);
    }
    // SAFETY: takeLocalFrontendDescriptor detached and removed the sole epoch
    // descriptor. Adopt immediately, before any validation or other JNI work.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    if raw != expected {
        return Err(DecodeError::InvalidResult);
    }
    Ok(fd)
}

pub(super) fn handover<'env, E>(
    env: &JNIEnv<'env>,
    service: JObject<'env>,
    generation: i64,
    result: JObject<'env>,
    decode: impl FnOnce(JObject<'env>) -> Result<DecodedDescriptor, E>,
    error: impl Fn(DecodeError) -> E,
) -> Result<(Result<AppliedTun, E>, bool), E> {
    let value = env
        .call_method(
            result,
            "getResult",
            "()Lnet/mullvad/talpid/model/CreateTunResult;",
            &[],
        )
        .and_then(|value| value.l())
        .map_err(|e| error(e.into()))?;
    let value = env.auto_local(value);
    let retained = env
        .call_method(result, "getPredecessorRetained", "()Z", &[])
        .and_then(|value| value.z())
        .map_err(|e| error(e.into()))?;
    let fd = decode(value.as_obj()).and_then(|decoded| {
        take(env, service, generation, decoded.raw)
            .map_err(error)
            .map(|fd| AppliedTun {
                fd,
                profile: decoded.profile,
                cause: decoded.cause,
            })
    });
    Ok((fd, retained))
}
