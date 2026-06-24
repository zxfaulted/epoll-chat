#include "e2e/e2e_protocol.h"

#include "crypto/crypto_core.h"
#include "protocol/wire.h"

#include <openssl/crypto.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint32_t min(uint32_t a, uint32_t b)
{
    if (a <= b)
    {
        return a;
    }
    else
    {
        return b;
    }
}

static uint32_t max(uint32_t a, uint32_t b)
{
    if (a >= b)
    {
        return a;
    }
    else
    {
        return b;
    }
}

// pairwise_key = KDF(
//     shared_secret,
//     salt,
//     info
// )

// info:
//"chat_v1"
// min(client_id_a, client_id_b)
// max(client_id_a, client_id_b)
// fingerprint_a
// fingerprint_b
// vko_pub_a
// vko_pub_b

int get_info(uint32_t client_id_a, uint32_t client_id_b, uint8_t* fingerprint_a,
             uint8_t* fingerprint_b, uint16_t fingerprint_len, uint8_t* vko_pub_a,
             uint8_t* vko_pub_b, uint16_t vko_len, uint8_t** out, uint16_t* out_len)
{
    if (!fingerprint_a || !fingerprint_b || !vko_pub_a || !vko_pub_b || !out || !out_len)
    {
        return -1;
    }
    if (client_id_a == client_id_b)
    {
        fprintf(stderr, "id of clients must be different\n");
        return -1;
    }
    int         ret  = -1;
    size_t      len  = 0;
    const char* text = "chat_v1";
    len += strlen(text);
    len += 4 * 2;               // client_id
    len += fingerprint_len * 2; // fingerprint
    len += vko_len * 2;         // vko
    uint8_t* buf = OPENSSL_malloc(len);
    if (!buf)
    {
        ossl_print_error("OPENSSL_malloc");
        goto cleanup;
    }
    uint8_t* p   = buf;
    size_t   off = 0;

    memcpy(p + off, text, strlen(text));
    off += strlen(text);

    uint32_t first = min(client_id_a, client_id_b);
    put_u32_be(p + off, first);
    off += sizeof(first);

    uint32_t second = max(client_id_a, client_id_b);
    put_u32_be(p + off, second);
    off += sizeof(second);

    if (first == client_id_a)
    {
        memcpy(p + off, fingerprint_a, fingerprint_len);
        off += fingerprint_len;

        memcpy(p + off, fingerprint_b, fingerprint_len);
        off += fingerprint_len;

        memcpy(p + off, vko_pub_a, vko_len);
        off += vko_len;

        memcpy(p + off, vko_pub_b, vko_len);
        off += vko_len;
    }
    else
    {
        memcpy(p + off, fingerprint_b, fingerprint_len);
        off += fingerprint_len;

        memcpy(p + off, fingerprint_a, fingerprint_len);
        off += fingerprint_len;

        memcpy(p + off, vko_pub_b, vko_len);
        off += vko_len;

        memcpy(p + off, vko_pub_a, vko_len);
        off += vko_len;
    }

    if (len > UINT16_MAX)
    {
        fprintf(stderr, "len is more than UINT16_MAX\n");
        goto cleanup;
    }
    if (off != len)
    {
        fprintf(stderr, "get_info internal length mismatch\n");
        goto cleanup;
    }
    *out     = buf;
    buf      = NULL;
    *out_len = (uint16_t)len;

    ret = 0;
cleanup:
    OPENSSL_free(buf);
    return ret;
}