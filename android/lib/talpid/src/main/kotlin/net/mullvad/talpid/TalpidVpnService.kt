package net.mullvad.talpid

import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import androidx.annotation.CallSuper
import androidx.core.content.getSystemService
import androidx.lifecycle.lifecycleScope
import arrow.core.Either
import arrow.core.Nel
import arrow.core.left
import arrow.core.mapOrAccumulate
import arrow.core.maxBy
import arrow.core.merge
import arrow.core.raise.ExperimentalRaiseAccumulateApi
import arrow.core.raise.accumulate
import arrow.core.raise.either
import arrow.core.right
import co.touchlab.kermit.Logger
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicLong
import kotlin.properties.Delegates.observable
import net.mullvad.mullvadvpn.lib.common.util.EstablishError.ParameterNotApplied
import net.mullvad.mullvadvpn.lib.common.util.establishSafe
import net.mullvad.mullvadvpn.lib.common.util.prepareVpnSafe
import net.mullvad.mullvadvpn.lib.model.PrepareError
import net.mullvad.talpid.model.CaptureHandoverResult
import net.mullvad.talpid.model.CreateTunResult
import net.mullvad.talpid.model.CreateTunResult.EstablishError
import net.mullvad.talpid.model.CreateTunResult.InvalidDnsServers
import net.mullvad.talpid.model.CreateTunResult.NotPrepared
import net.mullvad.talpid.model.CreateTunResult.OtherAlwaysOnApp
import net.mullvad.talpid.model.CreateTunResult.OtherLegacyAlwaysOnVpn
import net.mullvad.talpid.model.InetNetwork
import net.mullvad.talpid.model.TunConfig
import net.mullvad.talpid.util.TalpidSdkUtils.setMeteredIfSupported
import net.mullvad.talpid.util.UnderlyingConnectivityStatusResolver

@Suppress("TooManyFunctions")
open class TalpidVpnService : LifecycleVpnService() {
    private fun Builder.establishObserved() = run {
        establishEntries.incrementAndGet()
        // Android's caller-scoped getter reports false before an established VPN
        // exists. Establishment changes its validity without changing Settings.
        establishSafe().onRight { lockdownObserver?.refresh() }
    }

    private lateinit var localNetworkWatcher: LocalNetworkWatcher
    private lateinit var systemDnsAuthority: SystemDnsAuthority
    private var lockdownObserver: VpnLockdownObserver? = null
    private val localNetworkDemand = LocalNetworkDemand {
        if (it) localNetworkWatcher.start() else localNetworkWatcher.stop()
    }
    private val localPolicyRegistrationLock = Any()
    private var localPolicyDemandSequence = -1L
    private val localFrontendOwnership = LocalFrontendOwnership()
    private var captureRegistration = 0L
    private val captureObservers = mutableMapOf<Long, LocalCaptureNetworkObserver>()
    // Until native has decoded the complete result, this epoch still owns the
    // established descriptor. A lost acknowledgement is cleaned by exact finish.
    private val pendingCaptureDescriptors = mutableMapOf<Long, ParcelFileDescriptor>()
    private var activeTunStatus by
        observable<CreateTunResult?>(null) { _, oldTunStatus, _ ->
            val oldTunFd =
                when (oldTunStatus) {
                    is CreateTunResult.Success -> oldTunStatus.tunFd
                    is InvalidDnsServers -> oldTunStatus.tunFd
                    is CreateTunResult.InvalidIpv6Config -> oldTunStatus.tunFd
                    else -> null
                }

            if (oldTunFd != null) {
                ParcelFileDescriptor.adoptFd(oldTunFd).close()
            }
        }

    // Used by JNI
    lateinit var connectivityListener: ConnectivityListener

    @CallSuper
    override fun onCreate() {
        super.onCreate()
        connectivityListener =
            ConnectivityListener(
                @Suppress("UnsafeCallOnNullableType") getSystemService<ConnectivityManager>()!!,
                UnderlyingConnectivityStatusResolver(::protect),
            )
        connectivityListener.register(lifecycleScope)
        localNetworkWatcher = LocalNetworkWatcher(AndroidLocalNetworkSource(this), lifecycleScope)
        systemDnsAuthority =
            SystemDnsAuthority(
                { Build.VERSION.SDK_INT < Build.VERSION_CODES.Q || isLockdownEnabled },
                ::protect,
                localNetwork = { localNetworkWatcher.physicalNetworkHandle },
            )
        getSystemService<ConnectivityManager>()?.let(systemDnsAuthority::register)
    }

    @CallSuper
    override fun onDestroy() {
        synchronized(this) { invalidateCaptureObservation() }
        localNetworkWatcher.stop()
        systemDnsAuthority.close()
        lockdownObserver?.close()
        lockdownObserver = null
        super.onDestroy()
    }

    // Used by JNI. Attach is the only way to enable native delivery.
    @Suppress("Unused")
    fun attachLocalNetwork(registration: Long): Boolean =
        synchronized(localPolicyRegistrationLock) {
            localNetworkWatcher.attach(registration).also { attached ->
                if (attached) {
                    localPolicyDemandSequence = -1L
                    localNetworkDemand.policy(false)
                }
            }
        }

    fun setLocalNetworkEditorDemand(demanded: Boolean): Long {
        localNetworkDemand.editor(demanded)
        return localNetworkWatcher.minimumUsableSequence
    }

    // Used by JNI. Policy demand comes from the daemon, never a cached UI read.
    @Suppress("Unused")
    fun setLocalNetworkPolicyDemand(
        registration: Long,
        sequence: Long,
        demanded: Boolean,
    ): Boolean =
        synchronized(localPolicyRegistrationLock) {
            if (!localNetworkWatcher.registered(registration) || sequence < 0) return false
            if (sequence < localPolicyDemandSequence) return true
            localPolicyDemandSequence = sequence
            localNetworkDemand.policy(demanded)
            true
        }

    @Suppress("Unused")
    fun detachLocalNetwork(registration: Long): Boolean =
        synchronized(localPolicyRegistrationLock) {
            localNetworkWatcher.detach(registration).also { detached ->
                if (detached) {
                    localPolicyDemandSequence = -1L
                    localNetworkDemand.policy(false)
                }
            }
        }

    @Suppress("Unused")
    fun attachCaptureNetwork(registration: Long): Boolean =
        synchronized(this) {
            if (registration <= 0 || captureRegistration != 0L) return false
            captureRegistration = registration
            if (
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && ::systemDnsAuthority.isInitialized
            ) {
                lockdownObserver =
                    VpnLockdownObserver(
                            contentResolver,
                            Handler(Looper.getMainLooper()),
                            { isLockdownEnabled },
                            { LocalCaptureNetworkBridge.lockdownChanged(registration, it) },
                        )
                        .also { it.start() }
            }
            true
        }

    @Suppress("Unused")
    fun detachCaptureNetwork(registration: Long): Boolean =
        synchronized(this) {
            if (captureRegistration != registration) return false
            lockdownObserver?.close()
            lockdownObserver = null
            closeCaptureObservation()
            captureRegistration = 0
            true
        }

    @Suppress("Unused")
    fun bindLocalFrontend(generation: Long, interfaceName: String): Boolean =
        synchronized(this) {
            captureObservers[generation]?.bind(interfaceName) == true
        }

    // Used by JNI. Success reports the borrowed number; exact take transfers the
    // sole descriptor after conversion. This never enters the Native TUN cache.
    @Suppress("Unused")
    fun openLocalFrontend(
        generation: Long,
        routes: Array<String>,
        excludedPackages: Array<String> = emptyArray(),
        dnsServers: ArrayList<InetAddress> = arrayListOf(),
    ): CreateTunResult =
        synchronized(this) {
            val config = LocalFrontendConfig.parse(routes, dnsServers) ?: return EstablishError
            openFrontend(generation) {
                createLocalFrontend(generation, config, excludedPackages) {}
            }
        }

    /** Managed capture retains the upstream safe fallback and its sole descriptor. */
    @Suppress("Unused")
    fun openSecuredFrontend(generation: Long, config: TunConfig): CreateTunResult =
        synchronized(this) {
            if (!supportsCaptureObservation()) return EstablishError
            openFrontend(generation) { createSecuredFrontend(generation, config) {} }
        }

    @Suppress("Unused")
    fun handoverLocalFrontend(
        predecessor: Long,
        generation: Long,
        routes: Array<String>,
        excludedPackages: Array<String> = emptyArray(),
        dnsServers: ArrayList<InetAddress> = arrayListOf(),
    ): CaptureHandoverResult =
        synchronized(this) {
            val config =
                LocalFrontendConfig.parse(routes, dnsServers)
                    ?: return CaptureHandoverResult(
                        EstablishError,
                        localFrontendOwnership.predecessorCurrent(predecessor),
                    )
            handoverFrontend(predecessor, generation) { establishing ->
                createLocalFrontend(generation, config, excludedPackages, establishing)
            }
        }

    @Suppress("Unused")
    fun handoverSecuredFrontend(
        predecessor: Long,
        generation: Long,
        config: TunConfig,
    ): CaptureHandoverResult =
        synchronized(this) {
            if (!supportsCaptureObservation())
                return CaptureHandoverResult(
                    EstablishError,
                    localFrontendOwnership.predecessorCurrent(predecessor),
                )
            handoverFrontend(predecessor, generation) { establishing ->
                createSecuredFrontend(generation, config, establishing)
            }
        }

    private fun handoverFrontend(
        predecessor: Long,
        generation: Long,
        create: (() -> Unit) -> CreateTunResult,
    ): CaptureHandoverResult {
        if (!localFrontendOwnership.tryHandover(predecessor, generation))
            return CaptureHandoverResult(
                EstablishError,
                localFrontendOwnership.predecessorCurrent(predecessor),
            )
        var enteredEstablish = false
        val result =
            try {
                create {
                    enteredEstablish = true
                    localFrontendOwnership.establishing(generation)
                }
            } catch (_: RuntimeException) {
                EstablishError
            }
        // Both obligations remain native-owned, including failure/acknowledgement
        // loss. Only an exact finish after joined fd closure may release either.
        if (enteredEstablish && !result.isOpen)
            localFrontendOwnership.establishmentFailed(generation)
        return CaptureHandoverResult(result, !enteredEstablish)
    }

    private fun supportsCaptureObservation() = captureRegistration > 0L

    private fun openFrontend(generation: Long, create: () -> CreateTunResult): CreateTunResult {
        if (!localFrontendOwnership.tryFrontend(generation)) return EstablishError
        val result =
            try {
                create()
            } catch (_: RuntimeException) {
                EstablishError
            }
        if (!result.isOpen) {
            // No detached fd exists. Keep ownership if callback release fails.
            finishLocalFrontend(generation)
        }
        return result
    }

    private fun frontendEstablished(
        generation: Long,
        descriptor: ParcelFileDescriptor,
        observeCapture: Boolean,
    ): CreateTunResult {
        pendingCaptureDescriptors[generation] = descriptor
        onLocalFrontendChanged(true)
        if (observeCapture && captureRegistration > 0) {
            val observer =
                LocalCaptureNetworkObserver(
                    checkNotNull(getSystemService<ConnectivityManager>()),
                    captureRegistration,
                    generation,
                )
            captureObservers[generation] = observer
            observer.start()
        }
        return CreateTunResult.Success(descriptor.fd)
    }

    // Used by JNI only after every fallible result conversion has succeeded.
    // detachFd transfers the sole descriptor; no wrapper adopts it a second time.
    @Suppress("Unused")
    fun takeLocalFrontendDescriptor(generation: Long): Int =
        synchronized(this) {
            check(localFrontendOwnership.predecessorCurrent(generation))
            val descriptor = checkNotNull(pendingCaptureDescriptors[generation])
            val fd = descriptor.detachFd()
            pendingCaptureDescriptors.remove(generation)
            fd
        }

    private fun invalidateCaptureObservation() {
        captureObservers.values.forEach { it.invalidate() }
    }

    private fun closeCaptureObservation() {
        // Invalidate all epochs before the first fallible unregister.
        invalidateCaptureObservation()
        val pending = captureObservers.entries.iterator()
        while (pending.hasNext()) {
            pending.next().value.close()
            pending.remove()
        }
    }

    private fun createSecuredFrontend(
        generation: Long,
        config: TunConfig,
        establishing: () -> Unit,
    ): CreateTunResult = either {
        prepareVpnSafe().mapLeft { it.toCreateTunError() }.bind()
        val builder = Builder()
        val configured = builder.configureWith(config, managed = true)
        val errors = configured.fold({ it.toList() }, { emptyList() })
        val invalidDns =
            errors.filterIsInstance<ConfigError.InvalidDns>().flatMap { it.addresses }.toSet()
        val dns =
            config.dnsServers
                .filterNot { it in invalidDns }
                .ifEmpty {
                    listOf(InetAddress.getByName(FALLBACK_DUMMY_DNS_SERVER))
                }
        val applied =
            if (errors.any { it is ConfigError.InvalidIpv6 }) {
                config.copy(
                    addresses =
                        arrayListOf(
                            InetAddress.getByName(MANAGED_ADDRESS_IPV4),
                            InetAddress.getByName(MANAGED_ADDRESS_IPV6),
                        ),
                    routes =
                        arrayListOf(
                            InetNetwork(InetAddress.getByName(ROUTE_ALL_IPV4), 0),
                            InetNetwork(InetAddress.getByName(ROUTE_ALL_IPV6), 0),
                        ),
                    mtu = BLOCKING_MTU,
                    dnsServers = ArrayList(dns),
                )
            } else config.copy(dnsServers = ArrayList(dns))
        establishing()
        connectivityListener.invalidateNetworkStateCache()
        val descriptor = builder.establishObserved().mapLeft { EstablishError }.bind()
        frontendEstablished(generation, descriptor, observeCapture = true)
        val override = applied.takeIf { it != config }
        configured
            .mapLeft {
                it.maxBy { error -> error.priority }.toCreateTunError(descriptor.fd, override)
            }
            .bind()
        CreateTunResult.Success(descriptor.fd, override)
    }
        .merge()

    private fun createLocalFrontend(
        generation: Long,
        config: LocalFrontendConfig,
        excludedPackages: Array<String>,
        establishing: () -> Unit,
    ): CreateTunResult = either {
        prepareVpnSafe().mapLeft { it.toCreateTunError() }.bind()
        val builder = Builder()
        config.configure(
            { address, prefix -> builder.addAddress(address, prefix) },
            { builder.addRoute(it.address, it.prefixLength.toInt()) },
        )
        builder.setMtu(LOCAL_ONLY_MTU)
        config.dnsServers.forEach { builder.addDnsServer(it) }
        builder.setBlocking(false)
        builder.setMeteredIfSupported(false)
        builder.excludeApplications(excludedPackages.asList())
        establishing()
        connectivityListener.invalidateNetworkStateCache()
        val descriptor = builder.establishObserved().mapLeft { EstablishError }.bind()
        frontendEstablished(generation, descriptor, observeCapture = false)
    }
        .merge()

    @Suppress("Unused")
    fun finishLocalFrontend(generation: Long): Unit =
        synchronized(this) {
            if (!localFrontendOwnership.owns(generation)) return
            connectivityListener.invalidateNetworkStateCache()
            captureObservers[generation]?.invalidate()
            pendingCaptureDescriptors[generation]?.close()
            pendingCaptureDescriptors.remove(generation)
            captureObservers[generation]?.close()
            captureObservers.remove(generation)
            if (localFrontendOwnership.isLast(generation)) onLocalFrontendChanged(false)
            localFrontendOwnership.frontendFinished(generation)
        }

    @Suppress("Unused")
    fun isLocalFrontendActive(): Boolean =
        synchronized(this) { localFrontendOwnership.frontendActive }

    @Suppress("Unused")
    fun prepareLocalSocket(
        fd: Int,
        networkHandle: Long,
        sequence: Long,
        needsWifiName: Boolean,
    ): Int =
        synchronized(this) {
            if (!localFrontendOwnership.canPrepare) return LocalSocketPreparation.INACTIVE
            localNetworkWatcher.withCurrentNetwork(networkHandle, sequence, needsWifiName) {
                LocalSocketPreparation.prepare(fd, it, ::protect)
            }
        }

    protected open fun onLocalFrontendChanged(active: Boolean) = Unit

    @Suppress("Unused")
    fun systemDnsSnapshot(): net.mullvad.talpid.model.SystemDnsSnapshot? =
        systemDnsAuthority.snapshot()

    @Suppress("Unused")
    fun systemDnsCurrent(token: Long): Boolean = systemDnsAuthority.current(token)

    @Suppress("Unused") fun systemDnsFailureToken(): Long = systemDnsAuthority.failureToken()

    @Suppress("Unused")
    fun prepareSystemDns(fd: Int, token: Long): Int =
        synchronized(this) {
            if (localFrontendOwnership.canPrepare) systemDnsAuthority.prepare(fd, token)
            else LocalSocketPreparation.INACTIVE
        }

    protected fun hasOpenTun(): Boolean = synchronized(this) { activeTunStatus?.isOpen == true }

    /** Serialize foreground demotion with native frontend opening and finishing. */
    protected fun withoutLocalFrontend(action: () -> Unit): Unit =
        synchronized(this) {
            if (!localFrontendOwnership.frontendActive) action()
        }

    @CallSuper
    override fun onRevoke(): Unit =
        synchronized(this) {
            invalidateCaptureObservation()
            localFrontendOwnership.revoke()
        }

    // Used by JNI
    fun openTun(config: TunConfig): CreateTunResult =
        synchronized(this) {
            if (!localFrontendOwnership.tryUpstream()) return EstablishError
            createTun(config).merge().also {
                activeTunStatus = it
                if (!it.isOpen) localFrontendOwnership.upstreamClosed()
            }
        }

    // Used by JNI
    @Suppress("Unused")
    fun closeTun(): Unit =
        synchronized(this) {
            connectivityListener.invalidateNetworkStateCache()
            activeTunStatus = null
            localFrontendOwnership.upstreamClosed()
        }

    // Used by JNI
    @Suppress("Unused") fun bypass(socket: Int): Boolean = protect(socket)

    private fun createTun(
        config: TunConfig
    ): Either<CreateTunResult.Error, CreateTunResult.Success> = either {
        prepareVpnSafe().mapLeft { it.toCreateTunError() }.bind()

        val builder = Builder()
        val configureResult = builder.configureWith(config)

        connectivityListener.invalidateNetworkStateCache()
        val vpnInterfaceFd =
            builder
                .establishObserved()
                .onLeft {
                    Logger.w("Failed to establish tunnel $it")
                    if (it is ParameterNotApplied && config.hasIpv6Address) {
                        Logger.w("Try to turn off IPv6")
                    }
                }
                .mapLeft { EstablishError }
                .bind()

        val tunFd = vpnInterfaceFd.detachFd()

        configureResult
            .mapLeft { errors -> errors.maxBy { it.priority }.toCreateTunError(tunFd) }
            .bind()
        CreateTunResult.Success(tunFd)
    }

    @OptIn(ExperimentalRaiseAccumulateApi::class)
    private fun Builder.configureWith(
        config: TunConfig,
        managed: Boolean = false,
    ): Either<Nel<ConfigError>, Unit> = either {
        setMtu(config.mtu)
        setBlocking(false)
        setMeteredIfSupported(false)

        excludeApplications(config.excludedPackages)

        accumulate {
            accumulating { addAddressesAndRoutesSafe(config, managed).bind() }
            accumulating { addDnsServersSafe(config).bind() }
        }
    }

    private fun Builder.excludeApplications(packages: List<String>) {
        packages.forEach { app ->
            try {
                addDisallowedApplication(app)
            } catch (_: PackageManager.NameNotFoundException) {
                // Keep the stored exclusion so reinstalling the app applies it again.
                // Resolve at the actual Builder call: uninstall can race a prior query.
                Logger.w("Excluded application is not installed: $app")
            }
        }
    }

    // Blocking fallback for when we receive an invalid IPv6 config
    private fun Builder.invalidIpv6Setup(managed: Boolean) {
        addAddress(if (managed) MANAGED_ADDRESS_IPV4 else BLOCKING_ADDRESS_IPV4, IPV4_PREFIX_LENGTH)
        addAddress(if (managed) MANAGED_ADDRESS_IPV6 else BLOCKING_ADDRESS_IPV6, IPV6_PREFIX_LENGTH)
        addRoute(ROUTE_ALL_IPV4, 0)
        addRoute(ROUTE_ALL_IPV6, 0)
        // IPv6 have a minimum mtu of 1280, the daemon can send a lower mtu if IPv6 is disabled
        // Due to this we need to set a dummy mtu or the establish might fail
        setMtu(BLOCKING_MTU)
    }

    // To avoid leaks a config should either fully contain IPv6 or have no IPv6 configuration. A
    // partial IPv6 configuration, e.g. having no address but providing routes, will lead to traffic
    // routed outside the tunnel
    private fun TunConfig.validIpv6Routes(): Boolean =
        hasCompleteIpv6Configuration() || hasNoIpv6Configuration()

    /**
     * Checks for a complete IPv6 configuration, meaning at least one IPv6 address and one IPv6
     * route exist.
     */
    private fun TunConfig.hasCompleteIpv6Configuration() = hasIpv6Route && hasIpv6Address

    /** Checks that no IPv6 configuration (addresses, routes, or DNS) is present. */
    private fun TunConfig.hasNoIpv6Configuration() =
        !hasIpv6Address && !hasIpv6DnsServer && !hasIpv6Route

    private fun PrepareError.toCreateTunError() =
        when (this) {
            is PrepareError.OtherLegacyAlwaysOnVpn -> OtherLegacyAlwaysOnVpn
            is PrepareError.NotPrepared -> NotPrepared
            is PrepareError.OtherAlwaysOnApp -> OtherAlwaysOnApp(appName)
        }

    private fun ConfigError.toCreateTunError(tunFd: Int, appliedConfig: TunConfig? = null) =
        when (this) {
            is ConfigError.InvalidIpv6 ->
                CreateTunResult.InvalidIpv6Config(
                    addresses = addresses,
                    routes = routes,
                    dnsServers = dnsServers,
                    tunFd = tunFd,
                    appliedConfig = appliedConfig,
                )
            is ConfigError.InvalidDns ->
                InvalidDnsServers(
                    addresses = addresses,
                    tunFd = tunFd,
                    appliedConfig = appliedConfig,
                )
        }

    private fun Builder.addDnsServersSafe(
        config: TunConfig
    ): Either<ConfigError.InvalidDns, Builder> {
        // We don't care if adding DNS servers fails at this point, since we can still create a
        // tunnel to consume traffic and then notify daemon to later enter blocked state.
        val dnsConfigureResult =
            config.dnsServers.mapOrAccumulate {
                addDnsServerSafe(it).bind()
                Unit
            }

        // Never create a tunnel where all DNS servers are invalid or if none was ever set, since
        // apps then may leak DNS requests.
        // https://issuetracker.google.com/issues/337961996
        val shouldAddFallbackDns =
            dnsConfigureResult.fold(
                { invalidDnsServers -> invalidDnsServers.size == config.dnsServers.size },
                { addedDnsServers -> addedDnsServers.isEmpty() },
            )
        if (shouldAddFallbackDns) {
            Logger.w(
                "All DNS servers invalid or non set, using fallback DNS server to " +
                    "minimize leaks, dnsServers.isEmpty(): ${config.dnsServers.isEmpty()}"
            )
            addDnsServer(FALLBACK_DUMMY_DNS_SERVER)
        }
        return dnsConfigureResult.mapLeft { ConfigError.InvalidDns(addresses = it) }.map { this }
    }

    private fun Builder.addDnsServerSafe(dnsServer: InetAddress): Either<InetAddress, Builder> =
        Either.catch { addDnsServer(dnsServer) }
            .mapLeft {
                when (it) {
                    is IllegalArgumentException -> dnsServer
                    else -> throw it
                }
            }

    private fun Builder.addAddressesAndRoutesSafe(
        config: TunConfig,
        managed: Boolean = false,
    ): Either<ConfigError.InvalidIpv6, Builder> =
        if (config.validIpv6Routes()) {
            config.addresses.forEach { addAddress(it, it.prefixLength()) }
            config.routes.forEach { addRoute(it.address, it.prefixLength.toInt()) }
            right()
        } else {
            Logger.e("Bad Ipv6 config provided!")
            Logger.e("IPv6 address: ${config.hasIpv6Address}")
            Logger.e("IPv6 route: ${config.hasIpv6Route}")
            Logger.e("IPv6 DnsServer: ${config.hasIpv6DnsServer}")
            invalidIpv6Setup(managed)
            ConfigError.InvalidIpv6(
                    addresses = config.addresses,
                    routes = config.routes,
                    dnsServers = config.dnsServers,
                )
                .left()
        }

    private fun InetAddress.prefixLength(): Int =
        when (this) {
            is Inet4Address -> IPV4_PREFIX_LENGTH
            is Inet6Address -> IPV6_PREFIX_LENGTH
            else -> throw IllegalArgumentException("Invalid IP address (not IPv4 nor IPv6)")
        }

    companion object {
        private val establishEntries = AtomicLong()

        /** Process-lifetime Builder entry count, not successful descriptors or requests. */
        fun builderEstablishAttempts(): Long = establishEntries.get()

        const val FALLBACK_DUMMY_DNS_SERVER = "192.0.2.1"
        const val BLOCKING_ADDRESS_IPV4 = "10.0.0.1"
        const val BLOCKING_ADDRESS_IPV6 = "fd00::1"
        const val ROUTE_ALL_IPV4 = "0.0.0.0"
        const val ROUTE_ALL_IPV6 = "::"
        const val BLOCKING_MTU = 1280
        private const val LOCAL_ONLY_MTU = 1280
        private const val MANAGED_ADDRESS_IPV4 = "172.27.1.1"
        private const val MANAGED_ADDRESS_IPV6 = "fdf0:ce4a:801d::172:27:1:1"

        private const val IPV4_PREFIX_LENGTH = 32
        private const val IPV6_PREFIX_LENGTH = 128
    }
}

private sealed interface ConfigError {
    val priority: Int

    data class InvalidDns(val addresses: List<InetAddress>) : ConfigError {
        override val priority: Int = 1
    }

    data class InvalidIpv6(
        val addresses: List<InetAddress>,
        val routes: List<InetNetwork>,
        val dnsServers: List<InetAddress>,
    ) : ConfigError {
        override val priority: Int = 2
    }
}
