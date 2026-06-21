#ifndef PKT_BUILD_H
#define PKT_BUILD_H

#include <stddef.h>

#define NEED(p, end, x)                                                                            \
    do                                                                                             \
    {                                                                                              \
        if ((size_t)(end - p) < (size_t)(x))                                                       \
        {                                                                                          \
            goto cleanup;                                                                          \
        }                                                                                          \
    } while (0)

#endif