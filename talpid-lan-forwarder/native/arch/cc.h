#ifndef KRTEK_LWIP_ARCH_CC_H
#define KRTEK_LWIP_ARCH_CC_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define LWIP_NO_UNISTD_H 1
#define LWIP_PLATFORM_DIAG(x) do { printf x; } while (0)
#define LWIP_PLATFORM_ASSERT(x) do { fprintf(stderr, "lwIP assertion: %s\n", x); abort(); } while (0)

#endif
