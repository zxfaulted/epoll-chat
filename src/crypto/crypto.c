#define _POSIX_C_SOURCE 200809L

#include "crypto/crypto.h"

#include "crypto/crypto_core.h"
#include "crypto/ksi.h"
#include "storage/fs_utils.h"
#include "storage/pem_io.h"

#include <errno.h>
#include <limits.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int ensure_keys_dir(const char* name)
{
    if (ensure_dir("./keys", name) < 0)
    {
        return -1;
    }
    return 0;
}

int get_hash(FingerprintAlg fa, uint8_t* identity_pub, uint16_t identity_len, uint8_t** out,
             uint16_t* out_len)
{
    int ret = -1;
    if (!identity_pub || !out || !out_len)
    {
        return ret;
    }

    *out         = NULL;
    *out_len     = 0;
    uint8_t* buf = NULL;

    EVP_MD*     md  = NULL;
    EVP_MD_CTX* ctx = NULL;

    const char* name = NULL;
    switch (fa)
    {
        case FA_GOST2012_256:
            name = "md_gost12_256";
            break;
        case FA_GOST2012_512:
            name = "md_gost12_512";
            break;
        default:
            goto cleanup;
    }
    md = EVP_MD_fetch(NULL, name, NULL);
    if (!md)
    {
        ossl_print_error("EVP_MD_fetch failed");
        goto cleanup;
    }

    int md_size = EVP_MD_get_size(md);
    if (md_size <= 0 || md_size > UINT16_MAX)
    {
        ossl_print_error("EVP_MD_get_size failed");
        goto cleanup;
    }

    buf = OPENSSL_malloc(md_size);
    if (!buf)
    {
        ossl_print_error("OPENSSL_malloc failed");
        goto cleanup;
    }

    ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        ossl_print_error("EVP_MD_CTX_new failed failed");
        goto cleanup;
    }

    if (EVP_DigestInit_ex(ctx, md, NULL) <= 0)
    {
        ossl_print_error("EVP_DigestInit_ex failed");
        goto cleanup;
    }

    if (EVP_DigestUpdate(ctx, identity_pub, identity_len) <= 0)
    {
        ossl_print_error("EVP_DigestInit_ex failed");
        goto cleanup;
    }
    unsigned int len = 0;
    if (EVP_DigestFinal_ex(ctx, buf, &len) <= 0)
    {
        ossl_print_error("EVP_DigestFinal_ex failed");
        goto cleanup;
    }
    *out     = buf;
    buf      = NULL;
    *out_len = (uint16_t)len;
    ret      = 0;

cleanup:
    if (md)
    {
        EVP_MD_free(md);
    }
    if (ctx)
    {
        EVP_MD_CTX_free(ctx);
    }
    if (buf)
    {
        OPENSSL_free(buf);
    }
    return ret;
}

static int ends_with(const char* s, const char* suffix)
{
    size_t s_len      = strlen(s);
    size_t suffix_len = strlen(suffix);
    if (s_len < suffix_len)
    {
        return 0;
    }
    return strcmp(s + s_len - suffix_len, suffix) == 0;
}

EVP_PKEY* get_key(const char* name, const char* key_name)
{
    if (!name || is_name_safe(name) != 1 || !key_name)
    {
        return NULL;
    }

    EVP_PKEY* key = NULL;
    char      path[256];
    int       n = snprintf(path, sizeof(path), "./keys/%s/%s.pem", name, key_name);
    if (n < 0 || (size_t)n >= sizeof(path))
    {
        fprintf(stderr, "key_name too long\n");
        return NULL;
    }
    if (ends_with(key_name, "public"))
    {
        if (pem_read_public_key(path, &key) < 0)
        {
            fprintf(stderr, "pem_read_public_key failed\n");
            EVP_PKEY_free(key);
            return NULL;
        }
    }
    else if (ends_with(key_name, "private"))
    {
        if (pem_read_private_key(path, &key) < 0)
        {
            fprintf(stderr, "pem_read_private_key failed\n");
            EVP_PKEY_free(key);
            return NULL;
        }
    }
    return key;
}

// [1  packet_type]
// [4  sender_id]
// [4  to_client_id]
// [4 room_id]
// [8  epoch]
int build_aad(uint8_t aad[AAD_LEN], uint32_t sender_id, uint32_t to_client_id, uint32_t room_id,
              uint64_t epoch)
{
    if (!aad)
    {
        return -1;
    }
    size_t   off = 0;
    uint8_t* p   = aad;
    p[off++]     = PKT_ENC_ROOM_KEY;
    put_u32_be(p + off, sender_id);
    off += sizeof(sender_id);

    put_u32_be(p + off, to_client_id);
    off += sizeof(to_client_id);

    put_u32_be(p + off, room_id);
    off += sizeof(room_id);

    put_u64_be(p + off, epoch);
    off += sizeof(epoch);

    if (off != AAD_LEN)
    {
        return -1;
    }

    return 0;
}

int generate_keys_in_memory(GeneratedKeys* gk)
{
    EVP_PKEY* identity   = NULL;
    EVP_PKEY* vko        = NULL;
    gk->identity_private = NULL;
    gk->vko_private      = NULL;
    identity             = generate_identity_key();
    if (!identity)
    {
        fprintf(stderr, "generate_identity_key\n");
        return -1;
    }
    vko = generate_vko_key();
    if (!vko)
    {
        EVP_PKEY_free(identity);
        fprintf(stderr, "generate_identity_key\n");
        return -1;
    }
    gk->identity_private = identity;
    identity             = NULL;
    gk->vko_private      = vko;
    vko                  = NULL;

    return 0;
}

int save_keys_from_memory(const char* name, GeneratedKeys* gk)
{
    char path_private[256];
    char path_public[256];

    if (ensure_keys_dir(name) < 0)
    {
        return -1;
    }

    snprintf(path_private, sizeof(path_private), "./keys/%s/identity_private.pem", name);
    snprintf(path_public, sizeof(path_public), "./keys/%s/identity_public.pem", name);
    if (pem_write_private_key(path_private, gk->identity_private) < 0)
    {
        fprintf(stderr, "pem_write_private_key identity failed\n");
        return -1;
    }
    if (pem_write_public_key(path_public, gk->identity_private) < 0)
    {
        fprintf(stderr, "pem_write_public_key identity failed\n");
        return -1;
    }

    snprintf(path_private, sizeof(path_private), "./keys/%s/vko_private.pem", name);
    snprintf(path_public, sizeof(path_public), "./keys/%s/vko_public.pem", name);

    if (pem_write_private_key(path_private, gk->vko_private) < 0)
    {
        fprintf(stderr, "pem_write_private_key vko failed\n");
        return -1;
    }
    if (pem_write_public_key(path_public, gk->vko_private) < 0)
    {
        fprintf(stderr, "pem_write_public_key vko failed\n");
        return -1;
    }

    return 0;
}

int keys_exist(const char* name)
{
    if (is_name_safe(name) != 1)
    {
        return -1;
    }

    char path_private[256];
    char path_public[256];

    snprintf(path_private, sizeof(path_private), "./keys/%s/identity_private.pem", name);
    snprintf(path_public, sizeof(path_public), "./keys/%s/identity_public.pem", name);
    int identity_private_exists = file_exists(path_private);
    int identity_public_exists  = file_exists(path_public);
    snprintf(path_private, sizeof(path_private), "./keys/%s/vko_private.pem", name);
    snprintf(path_public, sizeof(path_public), "./keys/%s/vko_public.pem", name);
    int vko_private_exists = file_exists(path_private);
    int vko_public_exists  = file_exists(path_public);
    return identity_private_exists && identity_public_exists && vko_private_exists &&
           vko_public_exists;
}

// int client_join_room_with_key(int epfd, Client* c, uint32_t room_id,
//                               char password[MAX_PASSWORD_LEN])
// {
// }

void clear_generated_keys(GeneratedKeys* gk)
{
    if (!gk)
    {
        return;
    }
    EVP_PKEY_free(gk->identity_private);
    EVP_PKEY_free(gk->vko_private);
    memset(gk, 0, sizeof(*gk));
}

int load_keys_for_name(GeneratedKeys* gk, const char* user_name)
{
    EVP_PKEY* identity_private = NULL;
    EVP_PKEY* vko_private      = NULL;

    if (!gk || !user_name)
    {
        return -1;
    }

    clear_generated_keys(gk);

    if (read_private_keys(&identity_private, &vko_private, user_name) < 0 || !identity_private ||
        !vko_private)
    {
        EVP_PKEY_free(identity_private);
        EVP_PKEY_free(vko_private);
        return -1;
    }

    gk->identity_private = identity_private;
    gk->vko_private      = vko_private;

    return 0;
}
