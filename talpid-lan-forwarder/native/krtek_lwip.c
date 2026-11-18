/* Serialized bare-IP device adapter. Upstream owns all fragment algorithms. */
#include "krtek_lwip.h"
#include "lwip/init.h"
#include "lwip/ip.h"
#include "lwip/mem.h"
#include "lwip/nd6.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/prot/ip4.h"
#include "lwip/prot/ip6.h"
#include "lwip/raw.h"
#include "lwip/timeouts.h"
#include "lwip/udp.h"
#include <limits.h>
#include <string.h>

/* Context capacity is funded with the fixed input-node capacity, not per flow.
 * Retired handles need no slot: retained nodes keep their numeric provenance. */
#define CONTEXTS PBUF_POOL_SIZE
struct client { krtek_lwip_handle id; uint16_t mtu; };
struct tagged_node {
    struct pbuf_custom custom;
    struct pbuf *backing;
    krtek_lwip_handle handle;
    uint64_t scope;
};
static struct client clients[CONTEXTS];
static struct tagged_node nodes[PBUF_POOL_SIZE];
static struct netif device;
static uint64_t next_handle;
static uint32_t clock_ms;
static int initialized, entered;

/* The call frame is the only owner of borrowed foreign pointers. */
struct call {
    const krtek_lwip_callbacks *callbacks;
    void *context;
    krtek_lwip_handle handle;
    int32_t result;
    int reply;
};
static struct call current;

_Static_assert(sizeof(nodes) + sizeof(clients) <= 1048576,
    "fixed provenance and context tables fit the planned 1 MiB");
_Static_assert(MEM_ALIGNMENT >= 8, "IPv6 helper/header alignment");

u32_t sys_now(void) { return clock_ms; }

static struct client *find_client(krtek_lwip_handle id)
{
    size_t i;
    if (id == 0) return NULL;
    for (i = 0; i < CONTEXTS; ++i)
        if (clients[i].id == id) return &clients[i];
    return NULL;
}

static struct tagged_node *tag_of(const struct pbuf *p)
{
    uintptr_t address = (uintptr_t)p;
    uintptr_t first = (uintptr_t)&nodes[0];
    uintptr_t end = (uintptr_t)&nodes[PBUF_POOL_SIZE];
    if (address < first || address >= end ||
        (address - first) % sizeof(nodes[0]) != 0) return NULL;
    return &nodes[(address - first) / sizeof(nodes[0])];
}

static void free_node(struct pbuf *p)
{
    struct tagged_node *node = tag_of(p);
    struct pbuf *backing;
    LWIP_ASSERT("custom node belongs to fixed table", node && node->backing);
    backing = node->backing;
    node->backing = NULL;
    node->handle = 0;
    node->scope = 0;
    pbuf_free(backing);
}

static struct pbuf *input_copy(krtek_lwip_handle handle, uint64_t scope,
    const uint8_t *bytes, uint16_t length)
{
    struct pbuf *head = NULL;
    size_t offset = 0, i;
    while (offset < length) {
        struct tagged_node *node = NULL;
        struct pbuf *p;
        uint16_t chunk = (uint16_t)LWIP_MIN((size_t)PBUF_POOL_BUFSIZE,
            length - offset);
        for (i = 0; i < PBUF_POOL_SIZE; ++i)
            if (!nodes[i].backing) { node = &nodes[i]; break; }
        if (!node) goto fail;
        node->backing = pbuf_alloc(PBUF_RAW, chunk, PBUF_POOL);
        if (!node->backing) goto fail;
        LWIP_ASSERT("one backing pbuf per custom node", !node->backing->next);
        node->handle = handle;
        node->scope = scope;
        node->custom.custom_free_function = free_node;
        p = pbuf_alloced_custom(PBUF_RAW, chunk, PBUF_REF, &node->custom,
            node->backing->payload, chunk);
        if (!p) {
            pbuf_free(node->backing);
            node->backing = NULL;
            node->handle = node->scope = 0;
            goto fail;
        }
        memcpy(p->payload, bytes + offset, chunk);
        if (head) pbuf_cat(head, p); else head = p;
        offset += chunk;
    }
    return head;
fail:
    if (head) pbuf_free(head);
    return NULL;
}

static err_t capture(struct pbuf *p)
{
    uint8_t *copy;
    /* Timers/ingress can emit ICMP/ND. No flow owner exists for those packets.
     * Do not accidentally lend them a later reply's grant. */
    if (!current.reply || !current.callbacks || !current.callbacks->output)
        return ERR_OK;
    copy = mem_malloc(p->tot_len);
    if (!copy) { current.result = KRTEK_LWIP_FULL; return ERR_MEM; }
    if (pbuf_copy_partial(p, copy, p->tot_len, 0) != p->tot_len) {
        current.result = KRTEK_LWIP_INTERNAL;
        mem_free(copy);
        return ERR_BUF;
    }
    current.callbacks->output(current.context, copy, p->tot_len);
    mem_free(copy);
    return ERR_OK;
}

static err_t output4(struct netif *n, struct pbuf *p, const ip4_addr_t *a)
{ LWIP_UNUSED_ARG(n); LWIP_UNUSED_ARG(a); return capture(p); }
static err_t output6(struct netif *n, struct pbuf *p, const ip6_addr_t *a)
{ LWIP_UNUSED_ARG(n); LWIP_UNUSED_ARG(a); return capture(p); }

static u8_t complete(void *arg, struct raw_pcb *pcb, struct pbuf *p,
    const ip_addr_t *address)
{
    const struct pbuf *q;
    struct tagged_node *first = tag_of(p);
    krtek_lwip_transport transport;
    uint8_t *copy = NULL;
    uint16_t offset = ip_current_header_tot_len();
    uint16_t length;
    LWIP_UNUSED_ARG(arg);
    LWIP_UNUSED_ARG(address);
    current.result = KRTEK_LWIP_STALE;
    if (!first || !first->backing || !find_client(first->handle)) goto eaten;
    for (q = p; q; q = q->next) {
        struct tagged_node *node = tag_of(q);
        if (!node || !node->backing || node->handle != first->handle ||
            node->scope != first->scope) goto eaten;
    }
    /* A completion can be triggered by another client's injection. It must
     * never call that client's callback with a foreign retained assembly. */
    if (first->handle != current.handle) goto eaten;
    current.result = KRTEK_LWIP_UNSUPPORTED;
    if (pcb->protocol != KRTEK_LWIP_UDP && pcb->protocol != KRTEK_LWIP_TCP)
        goto eaten;
    if (IP_IS_V6(ip_current_src_addr()) &&
        IP6H_NEXTH(ip6_current_header()) != pcb->protocol) goto eaten;
    current.result = KRTEK_LWIP_MALFORMED;
    if (offset > p->tot_len) goto eaten;
    length = (uint16_t)(p->tot_len - offset);
    if (length < (pcb->protocol == KRTEK_LWIP_UDP ? 8 : 20)) goto eaten;
    memset(&transport, 0, sizeof(transport));
    transport.scope = first->scope;
    transport.protocol = pcb->protocol;
    if (IP_IS_V6(ip_current_src_addr())) {
        transport.family = KRTEK_LWIP_IPV6;
        memcpy(transport.source, ip_2_ip6(ip_current_src_addr())->addr, 16);
        memcpy(transport.destination, ip_2_ip6(ip_current_dest_addr())->addr, 16);
    } else {
        transport.family = KRTEK_LWIP_IPV4;
        memcpy(transport.source, &ip_2_ip4(ip_current_src_addr())->addr, 4);
        memcpy(transport.destination, &ip_2_ip4(ip_current_dest_addr())->addr, 4);
    }
    current.result = KRTEK_LWIP_OK;
    if (current.callbacks->complete) {
        copy = mem_malloc(length);
        if (!copy) { current.result = KRTEK_LWIP_FULL; goto eaten; }
        if (pbuf_copy_partial(p, copy, length, offset) != length) {
            current.result = KRTEK_LWIP_INTERNAL;
            goto eaten;
        }
        current.callbacks->complete(current.context, &transport, copy, length);
    }
eaten:
    if (copy) mem_free(copy);
    pbuf_free(p);
    return 1;
}

static err_t init_device(struct netif *n)
{
    n->name[0] = 'k'; n->name[1] = 'r';
    n->mtu = 1280;
    n->output = output4;
    n->output_ip6 = output6;
    return ERR_OK;
}

static int initialize(void)
{
    static const uint8_t protocols[] = {6, 17, 0, 43, 44, 60, 58};
    size_t i;
    if (initialized) return 1;
    lwip_init();
    if (!netif_add(&device, NULL, NULL, NULL, NULL, init_device, ip_input))
        return 0;
    netif_set_default(&device);
    netif_set_up(&device);
    netif_set_link_up(&device);
    for (i = 0; i < sizeof(protocols); ++i) {
        struct raw_pcb *pcb = raw_new_ip_type(IPADDR_TYPE_ANY, protocols[i]);
        /* Fixed configured pools guarantee these seven allocations at first init.
         * A failed invariant is terminal, never a partial-core reinitialization. */
        LWIP_ASSERT("funded raw PCB capacity", pcb != NULL);
        raw_recv(pcb, complete, NULL);
    }
    LWIP_ASSERT("enabled timer capacity", lwip_num_cyclic_timers <= MEMP_NUM_SYS_TIMEOUT);
    initialized = 1;
    return 1;
}

static void set_mtu(uint16_t mtu)
{
    device.mtu = mtu;
    /* Public ND configuration: never use a cached physical PMTU for this device. */
    nd6_clear_destination_cache();
}

static void set_address(const ip_addr_t *address)
{
    if (IP_IS_V6(address)) {
        netif_ip6_addr_set(&device, 0, ip_2_ip6(address));
        netif_ip6_addr_set_state(&device, 0, IP6_ADDR_PREFERRED);
    } else {
        netif_set_ipaddr(&device, ip_2_ip4(address));
    }
}

static void decode_address(ip_addr_t *address, uint8_t family, const uint8_t *bytes)
{
    memset(address, 0, sizeof(*address));
    if (family == KRTEK_LWIP_IPV6) {
        IP_SET_TYPE_VAL(*address, IPADDR_TYPE_V6);
        memcpy(ip_2_ip6(address)->addr, bytes, 16);
    } else {
        IP_SET_TYPE_VAL(*address, IPADDR_TYPE_V4);
        memcpy(&ip_2_ip4(address)->addr, bytes, 4);
    }
}

/* Check sizes using upstream wire types before any u16 narrowing. No fragment
 * identity/range state or transport authority is maintained here. */
static int32_t check_input(const uint8_t *bytes, size_t *length, ip_addr_t *dest)
{
    if (!bytes || !*length) return KRTEK_LWIP_MALFORMED;
    if (*length > UINT16_MAX) return KRTEK_LWIP_OVERSIZED;
    if ((bytes[0] >> 4) == 4) {
        struct ip_hdr hdr;
        size_t header, total, end;
        uint16_t frag;
        if (*length < IP_HLEN) return KRTEK_LWIP_MALFORMED;
        memcpy(&hdr, bytes, sizeof(hdr));
        header = IPH_HL_BYTES(&hdr); total = lwip_ntohs(IPH_LEN(&hdr));
        if (header < IP_HLEN || total < header || total > *length)
            return KRTEK_LWIP_MALFORMED;
        frag = lwip_ntohs(IPH_OFFSET(&hdr));
        end = (size_t)(frag & IP_OFFMASK) * 8 + total - header + IP_HLEN;
        if (end > UINT16_MAX) return KRTEK_LWIP_OVERSIZED;
        if (IPH_PROTO(&hdr) != 6 && IPH_PROTO(&hdr) != 17)
            return KRTEK_LWIP_UNSUPPORTED;
        decode_address(dest, 4, (const uint8_t *)&hdr.dest);
        *length = total;
        return KRTEK_LWIP_OK;
    }
    if ((bytes[0] >> 4) == 6) {
        struct ip6_hdr hdr;
        size_t total;
        if (*length < IP6_HLEN) return KRTEK_LWIP_MALFORMED;
        memcpy(&hdr, bytes, sizeof(hdr));
        total = (size_t)IP6H_PLEN(&hdr) + IP6_HLEN;
        if (total > UINT16_MAX) return KRTEK_LWIP_OVERSIZED;
        if (total > *length) return KRTEK_LWIP_MALFORMED;
        /* Extension-prefixed transports are deliberately unsupported. Refuse
         * them without a second header walker or retaining assemblies whose
         * extension-adjusted complete size this canonical boundary cannot know.
         * Raw rejection PCBs also eat extension types revealed by reassembly. */
        if (IP6H_NEXTH(&hdr) != IP6_NEXTH_TCP &&
            IP6H_NEXTH(&hdr) != IP6_NEXTH_UDP &&
            IP6H_NEXTH(&hdr) != IP6_NEXTH_FRAGMENT)
            return KRTEK_LWIP_UNSUPPORTED;
        if (IP6H_NEXTH(&hdr) == IP6_NEXTH_FRAGMENT) {
            struct ip6_frag_hdr fragment;
            size_t end;
            if (total < IP6_HLEN + IP6_FRAG_HLEN) return KRTEK_LWIP_MALFORMED;
            memcpy(&fragment, bytes + IP6_HLEN, sizeof(fragment));
            end = (lwip_ntohs(fragment._fragment_offset) & IP6_FRAG_OFFSET_MASK)
                + total - IP6_FRAG_HLEN;
            if (end > UINT16_MAX) return KRTEK_LWIP_OVERSIZED;
        }
        decode_address(dest, 6, (const uint8_t *)&hdr.dest);
        *length = total;
        return KRTEK_LWIP_OK;
    }
    return KRTEK_LWIP_MALFORMED;
}

uint32_t krtek_lwip_abi_version(void) { return KRTEK_LWIP_ABI_VERSION; }

int32_t krtek_lwip_open(krtek_lwip_handle *out)
{
    size_t i;
    if (!out) return KRTEK_LWIP_MALFORMED;
    *out = 0;
    if (entered) return KRTEK_LWIP_INTERNAL;
    entered = 1;
    if (next_handle == UINT64_MAX || !initialize()) {
        entered = 0; return KRTEK_LWIP_FULL;
    }
    for (i = 0; i < CONTEXTS; ++i) if (!clients[i].id) {
        clients[i].id = ++next_handle;
        clients[i].mtu = 1280;
        *out = clients[i].id;
        entered = 0; return KRTEK_LWIP_OK;
    }
    entered = 0; return KRTEK_LWIP_FULL;
}

int32_t krtek_lwip_ingest(krtek_lwip_handle handle, uint64_t scope,
    const uint8_t *bytes, size_t length, const krtek_lwip_callbacks *callbacks,
    void *context)
{
    struct client *client = find_client(handle);
    struct pbuf *p;
    ip_addr_t dest;
    int32_t result;
    if (!client) return KRTEK_LWIP_STALE;
    if (!callbacks || !scope) return KRTEK_LWIP_MALFORMED;
    if (entered) return KRTEK_LWIP_INTERNAL;
    result = check_input(bytes, &length, &dest);
    if (result != KRTEK_LWIP_OK) return result;
    if (IP_IS_V6(&dest) && client->mtu < 1280) return KRTEK_LWIP_UNSUPPORTED;
    entered = 1;
    current = (struct call){ callbacks, context, handle, KRTEK_LWIP_PENDING, 0 };
    set_mtu(client->mtu);
    set_address(&dest);
    p = input_copy(handle, scope, bytes, (uint16_t)length);
    if (!p) current.result = KRTEK_LWIP_FULL;
    else if (ip_input(p, &device) != ERR_OK) current.result = KRTEK_LWIP_MALFORMED;
    result = current.result;
    memset(&current, 0, sizeof(current));
    entered = 0;
    return result;
}

int32_t krtek_lwip_reply(krtek_lwip_handle handle,
    const krtek_lwip_transport *transport, uint16_t source_port,
    uint16_t destination_port, const uint8_t *bytes, size_t length,
    const krtek_lwip_callbacks *callbacks, void *context)
{
    struct client *client = find_client(handle);
    struct udp_pcb *pcb;
    struct pbuf *p;
    ip_addr_t source, dest;
    err_t error = ERR_MEM;
    int32_t result;
    if (!client) return KRTEK_LWIP_STALE;
    if (!transport || !callbacks || (!bytes && length) || !transport->scope)
        return KRTEK_LWIP_MALFORMED;
    if (transport->protocol != 17 ||
        (transport->family != 4 && transport->family != 6))
        return KRTEK_LWIP_UNSUPPORTED;
    /* Stock UDP binds port zero to an ephemeral port. Never silently rewrite
     * an explicit wire source. No normal listening physical peer uses port zero. */
    if (!source_port) return KRTEK_LWIP_UNSUPPORTED;
    if (transport->family == 4) {
        static const uint8_t zero[12];
        if (memcmp(transport->source + 4, zero, 12) ||
            memcmp(transport->destination + 4, zero, 12))
            return KRTEK_LWIP_MALFORMED;
    }
    if (length > (transport->family == 4 ? KRTEK_LWIP_MAX_UDP_IPV4 : KRTEK_LWIP_MAX_UDP_IPV6))
        return KRTEK_LWIP_OVERSIZED;
    if (transport->family == 6 && client->mtu < 1280) return KRTEK_LWIP_UNSUPPORTED;
    if (entered) return KRTEK_LWIP_INTERNAL;
    entered = 1;
    current = (struct call){ callbacks, context, handle, KRTEK_LWIP_OK, 1 };
    decode_address(&source, transport->family, transport->source);
    decode_address(&dest, transport->family, transport->destination);
    set_mtu(client->mtu);
    set_address(&source);
    pcb = udp_new_ip_type(IP_GET_TYPE(&source));
    p = pbuf_alloc(PBUF_TRANSPORT, (uint16_t)length, PBUF_RAM);
    if (pcb && p) {
        /* This transient PCB is only a synchronous app-facing encoder. */
        error = udp_bind(pcb, &source, source_port);
        if (error == ERR_OK && (!length || pbuf_take(p, bytes, (uint16_t)length) == ERR_OK))
            error = udp_sendto_if_src(pcb, p, &dest, destination_port, &device, &source);
    }
    if (p) pbuf_free(p);
    if (pcb) udp_remove(pcb);
    result = current.result;
    if (result == KRTEK_LWIP_OK && error != ERR_OK)
        result = error == ERR_MEM ? KRTEK_LWIP_FULL : KRTEK_LWIP_INTERNAL;
    memset(&current, 0, sizeof(current));
    entered = 0;
    return result;
}

int32_t krtek_lwip_set_mtu(krtek_lwip_handle handle, uint16_t mtu)
{
    struct client *client = find_client(handle);
    if (!client) return KRTEK_LWIP_STALE;
    if (entered) return KRTEK_LWIP_INTERNAL;
    if (mtu < 68) return KRTEK_LWIP_UNSUPPORTED;
    client->mtu = mtu;
    set_mtu(mtu);
    return KRTEK_LWIP_OK;
}

int32_t krtek_lwip_tick(uint32_t monotonic_ms)
{
    if (entered) return KRTEK_LWIP_INTERNAL;
    if ((uint32_t)(monotonic_ms - clock_ms) > INT32_MAX) return KRTEK_LWIP_MALFORMED;
    entered = 1;
    clock_ms = monotonic_ms;
    if (initialized) sys_check_timeouts();
    entered = 0;
    return KRTEK_LWIP_OK;
}

uint32_t krtek_lwip_next_timeout_ms(void)
{
    if (!initialized || entered) return UINT32_MAX;
    return sys_timeouts_sleeptime();
}

uint32_t krtek_lwip_scope_refs(krtek_lwip_handle handle, uint64_t scope)
{
    size_t i;
    uint32_t count = 0;
    if (!handle || !scope || entered) return 0;
    for (i = 0; i < PBUF_POOL_SIZE; ++i)
        if (nodes[i].backing && nodes[i].handle == handle && nodes[i].scope == scope)
            ++count;
    return count;
}

int32_t krtek_lwip_close(krtek_lwip_handle handle)
{
    struct client *client = find_client(handle);
    if (!client) return KRTEK_LWIP_STALE;
    if (entered) return KRTEK_LWIP_INTERNAL;
    client->id = 0;
    return KRTEK_LWIP_OK;
}
