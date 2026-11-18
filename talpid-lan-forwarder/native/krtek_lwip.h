#ifndef KRTEK_LWIP_H
#define KRTEK_LWIP_H

#include <stddef.h>
#include <stdint.h>

/* This is the entire Krtek ABI. No upstream lwIP structures cross it. */
#define KRTEK_LWIP_ABI_VERSION UINT32_C(1)
#define KRTEK_LWIP_OK INT32_C(0)
#define KRTEK_LWIP_PENDING INT32_C(1)
#define KRTEK_LWIP_FULL (-INT32_C(1))
#define KRTEK_LWIP_MALFORMED (-INT32_C(2))
#define KRTEK_LWIP_UNSUPPORTED (-INT32_C(3))
#define KRTEK_LWIP_OVERSIZED (-INT32_C(4))
#define KRTEK_LWIP_STALE (-INT32_C(5))
#define KRTEK_LWIP_INTERNAL (-INT32_C(6))
#define KRTEK_LWIP_IPV4 UINT8_C(4)
#define KRTEK_LWIP_IPV6 UINT8_C(6)
#define KRTEK_LWIP_TCP UINT8_C(6)
#define KRTEK_LWIP_UDP UINT8_C(17)
/* Minimal IP headers only; retained options/extensions reduce these limits. */
#define KRTEK_LWIP_MAX_UDP_IPV4 UINT32_C(65507)
#define KRTEK_LWIP_MAX_UDP_IPV6 UINT32_C(65487)

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t krtek_lwip_handle;

typedef struct {
    uint64_t scope;
    uint8_t family, protocol;
    /* Network-order address bytes; IPv4 uses bytes 0..3, then twelve zeroes. */
    uint8_t source[16], destination[16];
} krtek_lwip_transport;

/* All pointers are borrowed for the call only, never retained. Callbacks run
 * synchronously, cannot reenter the core, authorize, open sockets or unwind.
 * complete receives ONE COMPLETE transport segment, including its TCP/UDP
 * header. Metadata is from the processed IP context, not the last input piece.
 * Rust still validates full transport lengths/checksums before authorization.
 * output receives one already-built IP packet. Its caller supplies an explicit
 * reply owner and pre-funded capture batch, latching capture errors there:
 * stock fragmentation can ignore an output error and still return success. */
typedef struct {
    void (*complete)(void *, const krtek_lwip_transport *, const uint8_t *, size_t);
    void (*output)(void *, const uint8_t *, size_t);
} krtek_lwip_callbacks;

/* Handles are logical clients of ONE process-global core. Rust serializes EVERY
 * call (including timers, reference queries and close/free) with one mutex;
 * never wait for sockets/TUN while holding it. Validate pointers, lengths and
 * handles before use. A NULL data pointer is permitted only for length zero;
 * zero-length UDP payloads are legal. No native allocation is handed to Rust
 * to free. Required out/metadata/callback pointers must be non-NULL; individual
 * callback slots may be NULL when that operation is not being captured.
 *
 * A non-reused numeric scope and handle tag belong to EVERY input pbuf node.
 * Completion requires the same live handle/scope across ALL nodes. Tags never
 * retain Rust pointers. close invalidates the handle immediately, but retained
 * nodes may expire on stock timers; they cannot deliver after retirement.
 * scope_refs counts retained tagged nodes (including after handle close), so
 * Rust can release receive guards only after the final reference disappears.
 * Native funding and timer ownership outlive logical handles while state remains.
 * Unknown handles/scopes have zero references; invalid operations return STALE.
 */
uint32_t krtek_lwip_abi_version(void);
int32_t krtek_lwip_open(krtek_lwip_handle *);
int32_t krtek_lwip_ingest(krtek_lwip_handle, uint64_t scope,
    const uint8_t *, size_t, const krtek_lwip_callbacks *, void *);
/* Explicit WIRE reply endpoints, already reversed by Rust: source is the
 * original Local destination, destination is the app's fixed source. Ports
 * are host-order. Only UDP reply encoding is supported. Never reverse twice. */
int32_t krtek_lwip_reply(krtek_lwip_handle,
    const krtek_lwip_transport *, uint16_t source_port, uint16_t destination_port,
    const uint8_t *, size_t, const krtek_lwip_callbacks *, void *);
int32_t krtek_lwip_set_mtu(krtek_lwip_handle, uint16_t);
/* One process-relative monotonic millisecond clock, wrapping as lwIP u32_t.
 * Opening a handle never resets it. tick drives sys_now/sys_check_timeouts.
 * next_timeout_ms uses public sys_timeouts_sleeptime; UINT32_MAX means none. */
int32_t krtek_lwip_tick(uint32_t monotonic_ms);
uint32_t krtek_lwip_next_timeout_ms(void);
uint32_t krtek_lwip_scope_refs(krtek_lwip_handle, uint64_t scope);
int32_t krtek_lwip_close(krtek_lwip_handle);

#ifdef __cplusplus
}
#endif

#endif /* KRTEK_LWIP_H */
