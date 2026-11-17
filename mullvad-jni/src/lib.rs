#![cfg(target_os = "android")]

mod api;
mod capture_network;
mod classes;
mod initialization;
mod local_network;
mod problem_report;

use jnix::{
    FromJava, JnixEnv,
    jni::{
        JNIEnv,
        objects::{JClass, JObject},
    },
};
use mullvad_api::ApiEndpoint;
use mullvad_daemon::{
    Daemon, DaemonCommandChannel, DaemonCommandSender, DaemonConfig, cleanup_old_rpc_socket,
    exception_logging, logging,
    logging::{LogHandle, LogLocation},
    runtime::new_multi_thread,
    version,
};
use std::{collections::HashMap, sync::OnceLock};
use std::{
    ffi::CString,
    io,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, Once},
};
use talpid_error::ErrorExt;
use talpid_types::android::AndroidContext;

/// Mullvad daemon instance. It must be initialized and destroyed by `MullvadDaemon.initialize` and
/// `MullvadDaemon.shutdown`, respectively.
static DAEMON_CONTEXT: Mutex<Option<DaemonContext>> = Mutex::new(None);
static LOG_HANDLE: OnceLock<LogHandle> = OnceLock::new();

static LOAD_CLASSES: Once = Once::new();

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Failed to create global reference to Java object")]
    CreateGlobalReference(#[source] jnix::jni::errors::Error),

    #[error("Failed to get Java VM instance")]
    GetJvmInstance(#[source] jnix::jni::errors::Error),

    #[error("Failed to initialize logging: {0}")]
    InitializeLogging(String),

    #[error("Failed to initialize the mullvad daemon")]
    InitializeDaemon(#[source] mullvad_daemon::Error),

    #[error("Failed to init Tokio runtime")]
    InitTokio(#[source] io::Error),
}

/// Throw a Java exception and return if `result` is an error
macro_rules! ok_or_throw {
    ($env:expr_2021, $result:expr_2021) => {{
        match $result {
            Ok(val) => val,
            Err(err) => {
                let env = $env;
                env.throw(err.to_string())
                    .expect("Failed to throw exception");
                return;
            }
        }
    }};
}

#[derive(Debug)]
struct DaemonContext {
    runtime: tokio::runtime::Runtime,
    daemon_command_tx: DaemonCommandSender,
    running_daemon: Option<DaemonTask>,
    shutdown_failure: Option<mullvad_daemon::ShutdownFailure>,
    task_failure: Option<String>,
    local_network_registration: Option<local_network::LocalNetworkRegistration>,
    capture_network_registration: Option<capture_network::CaptureNetworkRegistration>,
}

type DaemonTask = tokio::task::JoinHandle<Result<(), mullvad_daemon::ShutdownFailure>>;

/// Spawn Mullvad daemon. There can only be a single instance, which must be shut down using
/// `MullvadDaemon.shutdown`. On success, nothing is returned. On error, an exception is thrown.
#[unsafe(no_mangle)]
pub extern "system" fn Java_net_mullvad_mullvadvpn_app_service_MullvadDaemon_initialize(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    vpn_service: JObject<'_>,
    rpc_socket_path: JObject<'_>,
    files_directory: JObject<'_>,
    cache_directory: JObject<'_>,
    api_endpoint: JObject<'_>,
    extra_metadata: JObject<'_>,
) {
    let mut ctx = DAEMON_CONTEXT.lock().unwrap();
    let env = JnixEnv::from(env);
    ok_or_throw!(
        &env,
        initialization::prepare(
            &mut ctx,
            |context| context.running_daemon.is_none()
                && context.task_failure.is_none()
                && context.shutdown_failure.is_some(),
            |context| {
                let failure = context
                    .shutdown_failure
                    .take()
                    .expect("checked shutdown failure");
                match context.runtime.block_on(failure.retry()) {
                    Ok(()) => Ok(()),
                    Err(failure) => {
                        let message = failure.to_string();
                        context.shutdown_failure = Some(failure);
                        Err(message)
                    }
                }
            },
        )
    );
    let files_dir = pathbuf_from_java(&env, files_directory);

    // In some cases, this function may be called multiple times for the same daemon process.
    // Since the tracing dispatcher can only be initialized once, we use a OnceLock to
    // reuse the existing log handle
    let log_handle = LOG_HANDLE
        .get_or_init(|| {
            start_logging(&files_dir)
                .map_err(Error::InitializeLogging)
                .unwrap()
        })
        .clone();

    version::log_version();

    log::info!("Pre-loading classes!");
    LOAD_CLASSES.call_once(|| env.preload_classes(classes::CLASSES.iter().cloned()));
    log::info!("Done loading classes");

    talpid_platform_metadata::set_extra_metadata(HashMap::from_java(&env, extra_metadata));

    let rpc_socket = pathbuf_from_java(&env, rpc_socket_path);
    let cache_dir = pathbuf_from_java(&env, cache_directory);

    let android_context = ok_or_throw!(&env, create_android_context(&env, vpn_service));
    log::info!("Created Android Context");
    let local_network_registration =
        local_network::LocalNetworkRegistration::attach(&env, &android_context);
    let capture_network_registration =
        capture_network::CaptureNetworkRegistration::attach(&env, &android_context);

    let api_endpoint = api::api_endpoint_from_java(&env, api_endpoint);

    log::info!("Starting daemon");
    let mut daemon = ok_or_throw!(
        &env,
        start(
            android_context,
            rpc_socket,
            files_dir,
            cache_dir,
            api_endpoint,
            log_handle
        )
    );

    daemon.local_network_registration = Some(local_network_registration);
    daemon.capture_network_registration = Some(capture_network_registration);
    *ctx = Some(daemon);
}

/// Shut down Mullvad daemon that was initialized using `MullvadDaemon.initialize`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_net_mullvad_mullvadvpn_app_service_MullvadDaemon_shutdown(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
) {
    let env = JnixEnv::from(env);
    let mut stored = DAEMON_CONTEXT.lock().unwrap();
    if let Some(context) = stored.as_mut() {
        let result = if let Some(task) = context.running_daemon.as_mut() {
            _ = context.daemon_command_tx.shutdown();
            let result = context.runtime.block_on(task);
            context.running_daemon = None;
            match result {
                Ok(result) => result,
                Err(error) => {
                    context.task_failure = Some(error.to_string());
                    ok_or_throw!(&env, Err::<(), _>(error));
                    unreachable!()
                }
            }
        } else if let Some(failure) = context.shutdown_failure.take() {
            context.runtime.block_on(failure.retry())
        } else {
            ok_or_throw!(
                &env,
                Err::<(), _>(
                    context
                        .task_failure
                        .as_deref()
                        .unwrap_or("Daemon shutdown lost its owner")
                )
            );
            unreachable!()
        };
        if let Err(failure) = result {
            let message = failure.to_string();
            context.shutdown_failure = Some(failure);
            ok_or_throw!(&env, Err::<(), _>(message));
        }
        stored.take();

        // Dropping the tokio runtime will block if there are any tasks in flight.
        // That is, until all async tasks yield *and* all blocking threads have stopped.
    }

    // Flush any remaining logs to file
    _ = LOG_HANDLE
        .get()
        .expect("Log handle has been initialized")
        .logfile_writer
        .clone() // clone the inner Arcs
        .flush();
}

fn start(
    android_context: AndroidContext,
    rpc_socket: PathBuf,
    files_dir: PathBuf,
    cache_dir: PathBuf,
    api_endpoint: Option<ApiEndpoint>,
    log_handle: LogHandle,
) -> Result<DaemonContext, Error> {
    #[cfg(not(feature = "api-override"))]
    if api_endpoint.is_some() {
        log::warn!("api_endpoint will be ignored since 'api-override' is not enabled");
    }

    spawn_daemon(
        android_context,
        rpc_socket,
        files_dir,
        cache_dir,
        api_endpoint.unwrap_or(ApiEndpoint::from_env_vars()),
        log_handle,
    )
}

fn spawn_daemon(
    android_context: AndroidContext,
    rpc_socket: PathBuf,
    files_dir: PathBuf,
    cache_dir: PathBuf,
    endpoint: ApiEndpoint,
    log_handle: LogHandle,
) -> Result<DaemonContext, Error> {
    let daemon_command_channel = DaemonCommandChannel::new();
    let daemon_command_tx = daemon_command_channel.sender();

    let runtime = new_multi_thread().build().map_err(Error::InitTokio)?;

    let daemon_config = DaemonConfig {
        rpc_socket_path: rpc_socket,
        log_dir: Some(files_dir.clone()),
        resource_dir: files_dir.clone(),
        settings_dir: files_dir,
        cache_dir,
        android_context,
        endpoint,
        log_handle,
    };

    let running_daemon =
        runtime.block_on(spawn_daemon_inner(daemon_config, daemon_command_channel))?;

    Ok(DaemonContext {
        runtime,
        daemon_command_tx,
        running_daemon: Some(running_daemon),
        shutdown_failure: None,
        task_failure: None,
        local_network_registration: None,
        capture_network_registration: None,
    })
}

async fn spawn_daemon_inner(
    daemon_config: DaemonConfig,
    daemon_command_channel: DaemonCommandChannel,
) -> Result<DaemonTask, Error> {
    cleanup_old_rpc_socket(&daemon_config.rpc_socket_path).await;

    let daemon = Daemon::start(daemon_config, daemon_command_channel)
        .await
        .map_err(Error::InitializeDaemon)?;

    let running_daemon = tokio::spawn(async move {
        let result = daemon.run().await;
        match &result {
            Ok(()) => log::info!("Mullvad daemon has stopped"),
            Err(error) => log::error!(
                "{}",
                error.display_chain_with_msg("Mullvad daemon exited with an error")
            ),
        }
        result
    });

    Ok(running_daemon)
}

fn start_logging(log_dir: &Path) -> Result<LogHandle, String> {
    let log_location = LogLocation {
        directory: log_dir.to_owned(),
        filename: PathBuf::from("daemon.log"),
    };
    let exception_log_path = CString::new(log_location.log_path().as_os_str().as_bytes())
        .map_err(|_| "Log file path contained interior null bytes: {log_file:?}")?;

    let log_handle = logging::init_logger(log::LevelFilter::Debug, Some(log_location), true)
        .map_err(|e| e.display_chain())?;

    log_panics::init();
    exception_logging::set_log_file(exception_log_path);
    exception_logging::enable();

    Ok(log_handle)
}

fn create_android_context(
    env: &JnixEnv<'_>,
    vpn_service: JObject<'_>,
) -> Result<AndroidContext, Error> {
    Ok(AndroidContext {
        jvm: Arc::new(env.get_java_vm().map_err(Error::GetJvmInstance)?),
        vpn_service: env
            .new_global_ref(vpn_service)
            .map_err(Error::CreateGlobalReference)?,
        local_network: local_network::new_feed(),
        capture_network: capture_network::new_feed(),
    })
}

fn pathbuf_from_java(env: &JnixEnv<'_>, path: JObject<'_>) -> PathBuf {
    PathBuf::from(String::from_java(env, path))
}
