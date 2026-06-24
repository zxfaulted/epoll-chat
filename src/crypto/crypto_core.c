#include "crypto/crypto_core.h"

#include "crypto/ksi.h"
#include "storage/fs_utils.h"
#include "storage/pem_io.h"

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef OSSL_KDF_PARAM_KBKDF_R
#define OSSL_KDF_PARAM_KBKDF_R "r"
#endif

static int get_exe_dir(char* out, size_t out_len)
{
    if (!out || out_len == 0)
    {
        return -1;
    }

    ssize_t n = readlink("/proc/self/exe", out, out_len - 1);
    if (n < 0 || (size_t)n >= out_len)
    {
        return -1;
    }

    out[n] = '\0';

    char* slash = strrchr(out, '/');
    if (!slash)
    {
        return -1;
    }

    *slash = '\0';
    return 0;
}

int ossl_init_crypto(OSSL_PROVIDER** dflt, OSSL_PROVIDER** gost)
{
    if (!dflt || !gost)
    {
        return -1;
    }

    char exe_dir[4096];
    char modules_dir[4096];

    if (get_exe_dir(exe_dir, sizeof(exe_dir)) < 0)
    {
        fprintf(stderr, "get_exe_dir failed\n");
        return -1;
    }

    int n = snprintf(modules_dir, sizeof(modules_dir), "%s/ossl-modules", exe_dir);
    if (n < 0 || (size_t)n >= sizeof(modules_dir))
    {
        fprintf(stderr, "modules_dir too long\n");
        return -1;
    }

    if (OSSL_PROVIDER_set_default_search_path(NULL, modules_dir) != 1)
    {
        ossl_print_error("OSSL_PROVIDER_set_default_search_path");
        return -1;
    }

    *dflt = OSSL_PROVIDER_load(NULL, "default");
    if (!*dflt)
    {
        ossl_print_error("OSSL_PROVIDER_load default");
        return -1;
    }

    *gost = OSSL_PROVIDER_load(NULL, "gostprov");
    if (!*gost)
    {
        ossl_print_error("OSSL_PROVIDER_load gostprov");
        OSSL_PROVIDER_unload(*dflt);
        *dflt = NULL;
        return -1;
    }

    return 0;
}

int ossl_destroy_crypto(OSSL_PROVIDER** dflt, OSSL_PROVIDER** gost)
{
    int ret = 0;
    if (dflt && *dflt)
    {
        if (!OSSL_PROVIDER_unload(*dflt))
        {
            ossl_print_error("OSSL_PROVIDER_unload FAILED");
            ret = -1;
        }
        *dflt = NULL;
    }
    if (gost && *gost)
    {
        if (!OSSL_PROVIDER_unload(*gost))
        {
            ossl_print_error("OSSL_PROVIDER_unload FAILED");
            ret = -1;
        }
        *gost = NULL;
    }
    return ret;
}

void ossl_print_error(const char* where)
{
    fprintf(stderr, "[OPENSSL ERROR] %s\n", where);
    ERR_print_errors_fp(stderr);
}

EVP_PKEY* generate_identity_key()
{
    return generate_key("gost2012_512");
}

EVP_PKEY* generate_vko_key()
{
    return generate_key("gost2012_512");
}

int create_keys(const char* name)
{

    int ret = -1;

    EVP_PKEY* identity = NULL;
    EVP_PKEY* vko      = NULL;
    char      path_private[256];
    char      path_public[256];

    if (ensure_keys_dir(name) < 0)
    {
        goto cleanup;
    }

    snprintf(path_private, sizeof(path_private), "./keys/%s/identity_private.pem", name);
    snprintf(path_public, sizeof(path_public), "./keys/%s/identity_public.pem", name);
    int private_exists = file_exists(path_private);
    int public_exists  = file_exists(path_public);
    if (!public_exists && !private_exists)
    {
        identity = generate_identity_key();
        if (!identity)
        {
            fprintf(stderr, "generate_identity_key failed\n");
            goto cleanup;
        }
        if (pem_write_private_key(path_private, identity) < 0)
        {
            fprintf(stderr, "pem_write_private_key identity failed\n");
            goto cleanup;
        }
        if (pem_write_public_key(path_public, identity) < 0)
        {
            fprintf(stderr, "pem_write_public_key identity failed\n");
            goto cleanup;
        }
    }
    else if ((public_exists && !private_exists) || (!public_exists && private_exists))
    {
        fprintf(stderr, "only one public or private identity key out of two available!\n");
        goto cleanup;
    }

    snprintf(path_private, sizeof(path_private), "./keys/%s/vko_private.pem", name);
    snprintf(path_public, sizeof(path_public), "./keys/%s/vko_public.pem", name);
    private_exists = file_exists(path_private);
    public_exists  = file_exists(path_public);
    if (!private_exists && !public_exists)
    {
        vko = generate_vko_key();
        if (!vko)
        {
            fprintf(stderr, "generate_vko_key failed\n");
            goto cleanup;
        }

        if (pem_write_private_key(path_private, vko) < 0)
        {
            fprintf(stderr, "pem_write_private_key vko failed\n");
            goto cleanup;
        }
        if (pem_write_public_key(path_public, vko) < 0)
        {
            fprintf(stderr, "pem_write_public_key vko failed\n");
            goto cleanup;
        }
    }
    else if ((public_exists && !private_exists) || (!public_exists && private_exists))
    {
        fprintf(stderr, "only one public or private vko key out of two available!\n");
        goto cleanup;
    }

    ret = 0;

cleanup:
    EVP_PKEY_free(identity);
    EVP_PKEY_free(vko);

    return ret;
}

int read_private_keys(EVP_PKEY** out_identity, EVP_PKEY** out_vko, const char* name)
{
    if (is_name_safe(name) != 1)
    {
        return -1;
    }

    char      path[256];
    EVP_PKEY* local_key;
    if (out_identity)
    {
        snprintf(path, sizeof(path), "./keys/%s/identity_private.pem", name);
        local_key = NULL;
        if (pem_read_private_key(path, &local_key) < 0)
        {
            fprintf(stderr, "pem_read_private_key failed\n");
            return -1;
        }
        if (!local_key)
        {
            fprintf(stderr, "pem_read_private_key failed\n");
            return -1;
        }
        *out_identity = local_key;
        local_key     = NULL;
    }
    if (out_vko)
    {
        snprintf(path, sizeof(path), "./keys/%s/vko_private.pem", name);
        local_key = NULL;
        if (pem_read_private_key(path, &local_key) < 0 || !local_key)
        {
            fprintf(stderr, "pem_read_private_key failed\n");
            if (out_identity && *out_identity)
            {
                EVP_PKEY_free(*out_identity);
                *out_identity = NULL;
            }
            return -1;
        }
        *out_vko  = local_key;
        local_key = NULL;
    }
    return 0;
}

EVP_PKEY* generate_key(const char* name)
{
    EVP_PKEY*     key = NULL;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);
    if (ctx == NULL)
    {
        ossl_print_error("EVP_PKEY_CTX_new_from_name");
        goto cleanup;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        ossl_print_error("EVP_PKEY_keygen_init");
        goto cleanup;
    }
    if (strcmp(name, "gost2012_512") == 0)
    {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "paramset", "A") < 0)
        {
            ossl_print_error("EVP_PKEY_CTX_ctrl_str");
            goto cleanup;
        }
    }
    if (EVP_PKEY_generate(ctx, &key) <= 0)
    {
        ossl_print_error("EVP_PKEY_generate");
        goto cleanup;
    }
    EVP_PKEY_CTX_free(ctx);
    return key;
cleanup:
    if (ctx)
    {
        EVP_PKEY_CTX_free(ctx);
    }
    if (key)
    {
        EVP_PKEY_free(key);
    }
    return NULL;
}

int derive_raw_secret(EVP_PKEY* my_vko_private, EVP_PKEY* peer, uint8_t** out, size_t* out_len)
{
    if (!my_vko_private || !peer || !out || !out_len)
    {
        return -1;
    }
    *out            = NULL;
    *out_len        = 0;
    uint8_t* key    = NULL;
    size_t   keylen = 0;
    int      ret    = -1;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(my_vko_private, NULL);
    if (!ctx)
    {
        ossl_print_error("EVP_PKEY_CTX_new failed");
        goto cleanup;
    }
    if (EVP_PKEY_derive_init(ctx) != 1)
    {
        ossl_print_error("EVP_PKEY_derive_init failed");
        goto cleanup;
    }
    if (EVP_PKEY_derive_set_peer(ctx, peer) != 1)
    {
        ossl_print_error("EVP_PKEY_derive_set_peer failed");
        goto cleanup;
    }
    if (EVP_PKEY_derive(ctx, NULL, &keylen) != 1)
    {
        ossl_print_error("EVP_PKEY_derive failed");
        goto cleanup;
    }
    key = OPENSSL_malloc(keylen);
    if (!key)
    {
        ossl_print_error("OPENSSL_malloc failed");
        goto cleanup;
    }
    if (EVP_PKEY_derive(ctx, key, &keylen) != 1)
    {
        ossl_print_error("EVP_PKEY_derive failed");
        goto cleanup;
    }
    *out     = key;
    key      = NULL;
    *out_len = keylen;
    ret      = 0;
cleanup:
    OPENSSL_free(key);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

// KDF_GOSTR3411_2012_256(K_in, label, seed)
// =
// HMAC_GOSTR3411_2012_256(
//     K_in,
//     0x01 || label || 0x00 || seed || 0x01 || 0x00
// )

int get_kdf(uint8_t* secret_key, uint16_t secret_key_len, const uint8_t* salt, uint16_t salt_len,
            uint8_t* info, uint16_t info_len, uint8_t* out_key, size_t out_key_len)
{
    if (!secret_key || (!salt && salt_len != 0) || !info || !out_key)
    {
        return -1;
    }
    if (out_key_len != 32)
    {
        fprintf(stderr, "get_kdf: keylen must be 32\n");
        return -1;
    }
    int          ret       = -1;
    EVP_KDF*     kdf       = NULL;
    EVP_KDF_CTX* ctx       = NULL;
    uint8_t*     gost_info = NULL;
    kdf                    = EVP_KDF_fetch(NULL, "KBKDF", NULL);
    if (!kdf)
    {

        ossl_print_error("EVP_KDF_fetch failed");
        goto cleanup;
    }

    ctx = EVP_KDF_CTX_new(kdf);
    if (!ctx)
    {
        ossl_print_error("EVP_KDF_CTX_new failed");
        goto cleanup;
    }

    size_t gost_info_len = info_len + 2;
    gost_info            = OPENSSL_malloc(gost_info_len);
    if (!gost_info)
    {
        ossl_print_error("OPENSSL_malloc");
        goto cleanup;
    }
    memcpy(gost_info, info, info_len);
    gost_info[info_len]     = 0x01;
    gost_info[info_len + 1] = 0x00;

    // counter || salt || 00 || info || L
    int r = 8; // счетчик counter

    // так как при use_l = 1 openssl добавит 4 байта, отключим эту возможность
    // и вручную добавим длину в 2 байта
    int        use_l         = 0;
    int        use_separator = 1; // 00 между salt и info
    OSSL_PARAM params[] = {OSSL_PARAM_int(OSSL_KDF_PARAM_KBKDF_USE_L, &use_l),
                           OSSL_PARAM_int(OSSL_KDF_PARAM_KBKDF_R, &r),
                           OSSL_PARAM_int(OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR, &use_separator),
                           OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, secret_key, secret_key_len),
                           OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, (void*)salt, salt_len),
                           OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO, gost_info, gost_info_len),
                           OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, "md_gost12_256", 0),
                           OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_MODE, "counter", 0),
                           OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_MAC, "HMAC", 0),
                           OSSL_PARAM_END};

    if (EVP_KDF_derive(ctx, out_key, out_key_len, params) != 1)
    {
        ossl_print_error("EVP_KDF_derive failed");
        goto cleanup;
    }

    ret = 0;
cleanup:
    EVP_KDF_CTX_free(ctx);
    OPENSSL_free(gost_info);
    EVP_KDF_free(kdf);
    return ret;
}