/* Object-symbol sizes provide real target sizeof values without running an
 * Android executable on the build host or exporting another production ABI. */
#include "../krtek_lwip.c"
const unsigned char krtek_sizeof_pbuf[sizeof(struct pbuf)] = {0};
const unsigned char krtek_sizeof_custom_node[sizeof(struct tagged_node)] = {0};
const unsigned char krtek_sizeof_context[sizeof(struct client)] = {0};
const unsigned char krtek_sizeof_nodes[sizeof(nodes)] = {0};
const unsigned char krtek_sizeof_contexts[sizeof(clients)] = {0};
const unsigned char krtek_sizeof_netif[sizeof(struct netif)] = {0};
const unsigned char krtek_sizeof_transport[sizeof(krtek_lwip_transport)] = {0};
const unsigned char krtek_sizeof_callbacks[sizeof(krtek_lwip_callbacks)] = {0};
