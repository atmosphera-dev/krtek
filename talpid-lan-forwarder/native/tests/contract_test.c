#include "../krtek_lwip.h"
#include "../krtek_lwip.h" /* Include guard is part of the public contract. */
#include <stdio.h>

_Static_assert(KRTEK_LWIP_ABI_VERSION == 1, "ABI version");
_Static_assert(KRTEK_LWIP_OK == 0 && KRTEK_LWIP_PENDING == 1, "success statuses");
_Static_assert(KRTEK_LWIP_FULL == -1 && KRTEK_LWIP_MALFORMED == -2, "refusal statuses");
_Static_assert(KRTEK_LWIP_UNSUPPORTED == -3 && KRTEK_LWIP_OVERSIZED == -4, "typed size refusal");
_Static_assert(KRTEK_LWIP_STALE == -5 && KRTEK_LWIP_INTERNAL == -6, "lifetime statuses");
_Static_assert(KRTEK_LWIP_IPV4 == 4 && KRTEK_LWIP_IPV6 == 6, "families");
_Static_assert(KRTEK_LWIP_TCP == 6 && KRTEK_LWIP_UDP == 17, "protocols");
_Static_assert(KRTEK_LWIP_MAX_UDP_IPV4 == 65535 - 20 - 8, "IPv4 ceiling");
_Static_assert(KRTEK_LWIP_MAX_UDP_IPV6 == 65535 - 40 - 8, "IPv6 ceiling");
_Static_assert(sizeof(krtek_lwip_handle) == 8, "handle width");
_Static_assert(offsetof(krtek_lwip_transport, scope) == 0, "scope offset");
_Static_assert(offsetof(krtek_lwip_transport, family) == 8, "family offset");
_Static_assert(offsetof(krtek_lwip_transport, protocol) == 9, "protocol offset");
_Static_assert(offsetof(krtek_lwip_transport, source) == 10, "source offset");
_Static_assert(offsetof(krtek_lwip_transport, destination) == 26, "destination offset");
#if defined(__i386__)
_Static_assert(sizeof(krtek_lwip_transport) == 44, "x86 transport size");
_Static_assert(_Alignof(krtek_lwip_transport) == 4, "x86 transport alignment");
#else
_Static_assert(sizeof(krtek_lwip_transport) == 48, "ARM/x86_64 transport size");
_Static_assert(_Alignof(krtek_lwip_transport) == 8, "ARM/x86_64 transport alignment");
#endif
_Static_assert(sizeof(krtek_lwip_callbacks) == 2 * sizeof(void *), "callback table size");
_Static_assert(_Alignof(krtek_lwip_callbacks) == _Alignof(void *), "callback alignment");
_Static_assert(offsetof(krtek_lwip_callbacks, complete) == 0, "completion offset");
_Static_assert(offsetof(krtek_lwip_callbacks, output) == sizeof(void *), "output offset");

/* Compile-time signature checks produce no unresolved engine references. */
#define SIGNATURE(name, type) _Static_assert(_Generic(&(name), type: 1, default: 0), #name)
SIGNATURE(krtek_lwip_abi_version, uint32_t (*)(void));
SIGNATURE(krtek_lwip_open, int32_t (*)(krtek_lwip_handle *));
SIGNATURE(krtek_lwip_ingest, int32_t (*)(krtek_lwip_handle, uint64_t,
    const uint8_t *, size_t, const krtek_lwip_callbacks *, void *));
SIGNATURE(krtek_lwip_reply, int32_t (*)(krtek_lwip_handle, const krtek_lwip_transport *,
    uint16_t, uint16_t, const uint8_t *, size_t, const krtek_lwip_callbacks *, void *));
SIGNATURE(krtek_lwip_set_mtu, int32_t (*)(krtek_lwip_handle, uint16_t));
SIGNATURE(krtek_lwip_tick, int32_t (*)(uint32_t));
SIGNATURE(krtek_lwip_next_timeout_ms, uint32_t (*)(void));
SIGNATURE(krtek_lwip_scope_refs, uint32_t (*)(krtek_lwip_handle, uint64_t));
SIGNATURE(krtek_lwip_close, int32_t (*)(krtek_lwip_handle));

int main(void)
{
    printf("stock_lwip_contract: ABI=%u transport=%zu/%zu callbacks=%zu/%zu; layout and 9 signatures passed\n",
        KRTEK_LWIP_ABI_VERSION, sizeof(krtek_lwip_transport), _Alignof(krtek_lwip_transport),
        sizeof(krtek_lwip_callbacks), _Alignof(krtek_lwip_callbacks));
    return 0;
}
