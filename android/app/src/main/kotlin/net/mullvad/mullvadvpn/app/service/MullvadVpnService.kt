package net.mullvad.mullvadvpn.app.service

import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.os.Binder
import android.os.Build
import android.os.IBinder
import androidx.core.content.getSystemService
import androidx.lifecycle.lifecycleScope
import arrow.atomic.AtomicInt
import co.touchlab.kermit.Logger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.filterIsInstance
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import net.mullvad.mullvadvpn.BuildConfig
import net.mullvad.mullvadvpn.app.service.migration.MigrateSplitTunneling
import net.mullvad.mullvadvpn.app.service.notifications.ForegroundNotificationManager
import net.mullvad.mullvadvpn.di.vpnServiceModule
import net.mullvad.mullvadvpn.lib.common.constant.connectAction
import net.mullvad.mullvadvpn.lib.common.constant.disconnectAction
import net.mullvad.mullvadvpn.lib.common.constant.reconnectAction
import net.mullvad.mullvadvpn.lib.endpoint.ApiEndpointFromIntentHolder
import net.mullvad.mullvadvpn.lib.grpc.ManagementService
import net.mullvad.mullvadvpn.lib.model.DisconnectReason
import net.mullvad.mullvadvpn.lib.model.TunnelState
import net.mullvad.mullvadvpn.lib.pushnotification.NotificationChannelFactory
import net.mullvad.mullvadvpn.lib.pushnotification.NotificationManager
import net.mullvad.mullvadvpn.lib.repository.ConnectionProxy
import net.mullvad.mullvadvpn.lib.repository.SettingsRepository
import net.mullvad.talpid.TalpidVpnService
import org.koin.android.ext.android.getKoin
import org.koin.core.context.loadKoinModules

private const val RELAY_LIST_ASSET_NAME = "relays.json"

class MullvadVpnService : MullvadVpnServiceLifecycle() {

    override lateinit var keyguardManager: KeyguardManager

    private lateinit var managementService: ManagementService
    private lateinit var settingsRepository: SettingsRepository
    private lateinit var migrateSplitTunneling: MigrateSplitTunneling
    private lateinit var apiEndpointFromIntentHolder: ApiEndpointFromIntentHolder
    override lateinit var connectionProxy: ConnectionProxy
    private lateinit var daemonConfig: DaemonConfig

    override lateinit var foregroundNotificationHandler: ForegroundNotificationManager

    override fun onCreate() {
        super.onCreate()
        Logger.i("MullvadVpnService: onCreate")

        loadKoinModules(listOf(vpnServiceModule))
        with(getKoin()) {
            // Needed to create all the notification channels
            get<NotificationChannelFactory>()

            managementService = get()
            settingsRepository = get()

            foregroundNotificationHandler =
                ForegroundNotificationManager(this@MullvadVpnService, get())
            get<NotificationManager>()

            daemonConfig = get()
            migrateSplitTunneling = get()
            apiEndpointFromIntentHolder = get()
            connectionProxy = get()
        }

        keyguardManager = getSystemService<KeyguardManager>()!!

        prepareFiles()
        migrateSplitTunneling.migrate()

        // If it is a debug build, and we have an api override in the intent, use it
        // This is for injecting hostname and port for our mock api tests
        val intentApiOverride = apiEndpointFromIntentHolder.apiEndpointOverride
        val updatedConfig =
            if (BuildConfig.DEBUG && intentApiOverride != null) {
                daemonConfig.copy(apiEndpointOverride = intentApiOverride)
            } else {
                daemonConfig
            }
        Logger.i("Start daemon")
        startDaemon(updatedConfig)

        Logger.i("Start management service")
        managementService.start()

        lifecycleScope.launch {
            settingsRepository.localNetworkEditorDemand.collect(::setLocalNetworkEditorDemand)
        }

        observeNonblockingErrors(managementService.tunnelState)
    }

    private fun startDaemon(daemonConfig: DaemonConfig) =
        with(daemonConfig) {
            MullvadDaemon.initialize(
                vpnService = this@MullvadVpnService,
                rpcSocketPath = rpcSocket.absolutePath,
                filesDirectory = filesDir.absolutePath,
                cacheDirectory = cacheDir.absolutePath,
                apiEndpointOverride = apiEndpointOverride,
                extraMetadata = mapOf("flavor" to BuildConfig.FLAVOR),
            )
            Logger.i("MullvadVpnService: Daemon initialized")
        }

    override fun onDestroy() {
        super.onDestroy()
        Logger.i("MullvadVpnService: onDestroy")
        managementService.stop()
        Logger.i("Shutdown MullvadDaemon")
        try {
            MullvadDaemon.shutdown()
            Logger.i("Shutdown complete")
        } catch (error: Exception) {
            // JNI retains the runtime and exact release owner for an explicit
            // shutdown retry. An uncaught lifecycle exception would kill it.
            Logger.e("Daemon shutdown incomplete; cleanup ownership retained", error)
        }
    }

    private fun Context.prepareFiles() {
        extractAndOverwriteIfAssetMoreRecent(
            RELAY_LIST_ASSET_NAME,
            BuildConfig.REQUIRE_BUNDLED_RELAY_FILE,
        )
    }

    companion object {
        init {
            System.loadLibrary("mullvad_jni")
        }
    }
}

/** The concrete Android service inherits this wiring; native startup stays in its subclass. */
abstract class MullvadVpnServiceLifecycle : TalpidVpnService() {
    protected abstract val keyguardManager: KeyguardManager
    protected abstract val connectionProxy: ConnectionProxy
    protected abstract val foregroundNotificationHandler: ForegroundNotificationManager
    protected open val commandScope: CoroutineScope
        get() = lifecycleScope

    // The same service instance owns both bindings and capture lifetime.
    private val bindCount = AtomicInt()

    protected fun observeNonblockingErrors(states: Flow<TunnelState>) = commandScope.launch {
        states
            .filterIsInstance<TunnelState.Error>()
            .filter { !it.errorState.isBlocking }
            .collect {
                withoutLocalFrontend { foregroundNotificationHandler.stopForeground() }
            }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Logger.i(
            "onStartCommand (intent=$intent, action=${intent?.action}, flags=$flags, startId=$startId)"
        )

        val startResult = platformStartCommand { super.onStartCommand(intent, flags, startId) }

        dispatchVpnServiceCommand(
            action = intent?.action,
            packageName = packageName,
            keyguardLocked = keyguardManager.isKeyguardLocked,
            actions =
                VpnServiceCommandActions(
                    startForeground = foregroundNotificationHandler::startForeground,
                    connect = {
                        commandScope.launch {
                            val changed =
                                connectionProxy
                                    .connectWithoutPermissionCheck()
                                    .fold({ "error" }, { it.toString() })
                            Logger.i(
                                "VPN command completed action=${intent?.action} startId=$startId changed=$changed"
                            )
                        }
                    },
                    reconnect = { commandScope.launch { connectionProxy.reconnect() } },
                    disconnect = {
                        commandScope.launch {
                            connectionProxy.disconnect(
                                DisconnectReason.USER_INITIATED_NOTIFICATION_TILE
                            )
                        }
                    },
                    stopUnboundForeground = {
                        if (bindCount.get() == 0) {
                            withoutLocalFrontend { foregroundNotificationHandler.stopForeground() }
                        }
                    },
                ),
        )

        return startResult
    }

    override fun onBind(intent: Intent?): IBinder {
        val count = bindCount.incrementAndGet()
        Logger.i("onBind: $intent, bindCount: $count")

        if (intent.isFromSystem()) {
            Logger.i("onBind was from system")
            foregroundNotificationHandler.startForeground()
        }

        // We always need to return a binder. If the system binds to our VPN service, VpnService
        // will return a binder that shall be user, otherwise we return an empty dummy binder to
        // keep connection service alive since the actual communication happens over gRPC.
        return platformBind { super.onBind(intent) } ?: emptyBinder()
    }

    override fun onRebind(intent: Intent?) {
        super.onRebind(intent)
        val count = bindCount.incrementAndGet()
        Logger.i("onRebind: $intent, bindCount: $count")

        if (intent.isFromSystem()) {
            Logger.i("onRebind from system")
            foregroundNotificationHandler.startForeground()
        }
    }

    protected open fun platformStartCommand(call: () -> Int): Int = call()

    protected open fun platformBind(call: () -> IBinder?): IBinder? = call()

    private fun emptyBinder() =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            Binder(this.toString())
        } else {
            Binder()
        }

    override fun onRevoke() {
        super.onRevoke()
        Logger.d("onRevoke")
        runBlocking { connectionProxy.disconnect(DisconnectReason.SYSTEM_REVOKE) }
    }

    override fun onUnbind(intent: Intent): Boolean {
        val count = bindCount.decrementAndGet()
        Logger.i("onUnbind: $intent, bindCount: $count")

        // Foreground?
        if (intent.isFromSystem()) {
            Logger.i("onUnbind from system")
            withoutLocalFrontend { foregroundNotificationHandler.stopForeground() }
        }

        return true
    }

    override fun onLocalFrontendChanged(active: Boolean) {
        if (active) foregroundNotificationHandler.startForeground()
        else if (bindCount.get() == 0 && !hasOpenTun()) {
            foregroundNotificationHandler.stopForeground()
        }
    }

    // If an intent is from the system it is because of the OS starting/stopping the VPN.
    private fun Intent?.isFromSystem(): Boolean {
        return this?.action == SERVICE_INTERFACE
    }
}

// Keep the upstream command order independent of capture lifetime. The callbacks
// are the service's effects; this seam also avoids loading JNI in command tests.
internal fun TalpidVpnService.dispatchVpnServiceCommand(
    action: String?,
    packageName: String,
    keyguardLocked: Boolean,
    actions: VpnServiceCommandActions,
) =
    with(actions) {
        when {
            keyguardLocked -> Logger.i("Keyguard is locked, ignoring command")
            action == android.net.VpnService.SERVICE_INTERFACE ||
                action == connectAction(packageName) -> {
                startForeground()
                connect()
            }
            action == reconnectAction(packageName) -> {
                startForeground()
                reconnect()
            }
            action == disconnectAction(packageName) -> {
                startForeground()
                disconnect()
                stopUnboundForeground()
            }
            else -> Unit
        }
    }

internal class VpnServiceCommandActions(
    val startForeground: () -> Unit,
    val connect: () -> Unit,
    val reconnect: () -> Unit,
    val disconnect: () -> Unit,
    val stopUnboundForeground: () -> Unit,
)
