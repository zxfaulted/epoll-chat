#define _POSIX_C_SOURCE 200809L

#include "crypto.h"
#include "ksi.h"
#include "net.h"
#include "protocol.h"
#include <errno.h>
#include <limits.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef OSSL_KDF_PARAM_KBKDF_R
#define OSSL_KDF_PARAM_KBKDF_R "r"
#endif

void put_u16_be(uint8_t* p, uint16_t v)
{
    p[0] = (uint8_t)((v >> 8) & 0xFF);
    p[1] = (uint8_t)(v & 0xFF);
}

uint16_t get_u16_be(const uint8_t* p)
{
    return (uint16_t)p[0] << 8 | (uint16_t)p[1];
}

void put_u32_be(uint8_t* p, uint32_t v)
{
    p[0] = (uint8_t)((v >> 24) & 0xFF);
    p[1] = (uint8_t)((v >> 16) & 0xFF);
    p[2] = (uint8_t)((v >> 8) & 0xFF);
    p[3] = (uint8_t)(v & 0xFF);
}

uint32_t get_u32_be(const uint8_t* p)
{
    return ((uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | (uint32_t)p[3]);
}

void put_u64_be(uint8_t* p, uint64_t v)
{
    p[0] = (uint8_t)((v >> 56) & 0xFF);
    p[1] = (uint8_t)((v >> 48) & 0xFF);
    p[2] = (uint8_t)((v >> 40) & 0xFF);
    p[3] = (uint8_t)((v >> 32) & 0xFF);
    p[4] = (uint8_t)((v >> 24) & 0xFF);
    p[5] = (uint8_t)((v >> 16) & 0xFF);
    p[6] = (uint8_t)((v >> 8) & 0xFF);
    p[7] = (uint8_t)(v & 0xFF);
}

uint64_t get_u64_be(const uint8_t* p)
{
    return ((uint64_t)p[0] << 56 | (uint64_t)p[1] << 48 | (uint64_t)p[2] << 40 |
            (uint64_t)p[3] << 32 | (uint64_t)p[4] << 24 | (uint64_t)p[5] << 16 |
            (uint64_t)p[6] << 8 | (uint64_t)p[7]);
}

int file_exists(const char* path)
{
    struct stat st;

    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

int ensure_keys_dir(const char* name)
{
    if (is_name_safe(name) != 1)
    {
        fprintf(stderr, "name is not safe\n");
        return -1;
    }
    if (mkdir("./keys", 0700) < 0 && errno != EEXIST)
    {
        perror("mkdir");
        return -1;
    }
    char path_with_name[256];
    snprintf(path_with_name, sizeof(path_with_name), "./keys/%s/", name);
    if (mkdir(path_with_name, 0700) < 0 && errno != EEXIST)
    {
        perror("mkdir");
        return -1;
    }
    return 0;
}

void ossl_print_error(const char* where)
{
    fprintf(stderr, "[OPENSSL ERROR] %s\n", where);
    ERR_print_errors_fp(stderr);
}

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

int kb_clear(KeyBundle* kb)
{
    if (!kb)
    {
        return -1;
    }

    OPENSSL_free(kb->fingerprint);
    OPENSSL_free(kb->identity_pub);
    OPENSSL_free(kb->signature);
    OPENSSL_free(kb->vko_pub);

    memset(kb, 0, sizeof(KeyBundle));
    return 0;
}

int kb_free(KeyBundle* kb)
{
    if (!kb)
    {
        return -1;
    }
    kb_clear(kb);
    free(kb);
    return 0;
}

int key_to_der_pub(EVP_PKEY* key, uint8_t** out, uint16_t* out_len)
{
    int ret = -1;
    if (!key || !out || !out_len)
    {
        return ret;
    }
    unsigned char* der = NULL;
    *out               = NULL;
    *out_len           = 0;

    int bytes = i2d_PUBKEY(key, &der);
    if (bytes <= 0)
    {
        ossl_print_error("i2d_PUBKEY failed");
        goto cleanup;
    }
    if (bytes > UINT16_MAX)
    {
        ossl_print_error("i2d_PUBKEY failed");
        goto cleanup;
    }
    *out_len = bytes;
    *out     = (uint8_t*)der;
    der      = NULL;
    ret      = 0;
cleanup:
    OPENSSL_free(der);
    return ret;
}

int der_to_key_pub(EVP_PKEY** out, uint8_t* in, uint16_t in_len)
{
    if (!out || !in)
    {
        return -1;
    }
    const unsigned char* p   = in;
    EVP_PKEY*            key = NULL;
    d2i_PUBKEY(&key, &p, in_len);
    if (!key || p != in + in_len)
    {
        ossl_print_error("d2i_PUBKEY failed");
        return -1;
    }
    *out = key;

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

int get_sign_kb(KeyBundle* kb, EVP_PKEY* private_key, unsigned char** out, size_t* out_len)
{
    int            ret     = -1;
    unsigned char* sigret  = NULL;
    size_t         siglen  = 0;
    EVP_MD*        md      = NULL;
    EVP_MD_CTX*    ctx     = NULL;
    uint8_t*       buf     = NULL;
    uint16_t       buf_len = 0;
    if (!kb || !private_key || !out || !out_len)
    {
        return -1;
    }
    *out     = NULL;
    *out_len = 0;

    md = EVP_MD_fetch(NULL, "md_gost12_512", NULL);
    if (!md)
    {
        goto cleanup;
    }

    ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        goto cleanup;
    }

    if (EVP_DigestSignInit(ctx, NULL, md, NULL, private_key) <= 0)
    {
        ossl_print_error("EVP_DigestSignInit failed");
        goto cleanup;
    }

    if (serialize_key_bundle_to_sign(kb, &buf, &buf_len) < 0)
    {
        fprintf(stderr, "serialize_key_bundle_to_sign failed\n");
        goto cleanup;
    }

    if (EVP_DigestSignUpdate(ctx, buf, buf_len) <= 0)
    {
        ossl_print_error("EVP_DigestSignUpdate failed");
        goto cleanup;
    }

    if (EVP_DigestSignFinal(ctx, NULL, &siglen) <= 0)
    {
        ossl_print_error("EVP_DigestSignFinal failed");
        goto cleanup;
    }
    sigret = OPENSSL_malloc(siglen);
    if (!sigret)
    {
        ossl_print_error("OPENSSL_malloc failed");
        goto cleanup;
    }

    if (EVP_DigestSignFinal(ctx, sigret, &siglen) <= 0)
    {
        ossl_print_error("EVP_DigestSignFinal failed");
        goto cleanup;
    }
    *out     = sigret;
    *out_len = siglen;
    sigret   = NULL;
    ret      = 0;
cleanup:
    OPENSSL_free(buf);
    OPENSSL_free(sigret);
    EVP_MD_free(md);
    EVP_MD_CTX_free(ctx);

    return ret;
}

// возвращает
// 1 правильная подпись
// 0 неправильная
// все остальное - ошибка
int verify_sign(KeyBundle* kb, EVP_PKEY* public_key)
{
    if (!kb || !public_key)
    {
        return -1;
    }

    int         ret      = -1;
    EVP_MD*     md       = NULL;
    EVP_MD_CTX* ctx      = NULL;
    uint8_t*    data     = NULL;
    uint16_t    data_len = 0;

    md = EVP_MD_fetch(NULL, "md_gost12_512", NULL);
    if (!md)
    {
        ossl_print_error("EVP_MD_fetch");
        goto cleanup;
    }
    ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        ossl_print_error("EVP_MD_CTX_new\n");
        goto cleanup;
    }

    if (EVP_DigestVerifyInit(ctx, NULL, md, NULL, public_key) <= 0)
    {
        fprintf(stderr, "EVP_DigestVerifyInit failed\n");
        goto cleanup;
    }

    if (serialize_key_bundle_to_sign(kb, &data, &data_len) < 0)
    {
        fprintf(stderr, "serialize_key_bundle_to_sign failed\n");
        goto cleanup;
    }

    if (EVP_DigestVerifyUpdate(ctx, data, data_len) <= 0)
    {
        ossl_print_error("EVP_DigestVerifyUpdate failed");
        goto cleanup;
    }

    int rc = EVP_DigestVerifyFinal(ctx, kb->signature, kb->signature_len);
    if (rc == 1)
    {
        ret = 1;
    }
    else if (rc == 0)
    {
        ret = 0;
    }
    else
    {
        ossl_print_error("EVP_DigestVerifyFinal failed\n");
        goto cleanup;
    }

cleanup:
    EVP_MD_free(md);
    EVP_MD_CTX_free(ctx);
    OPENSSL_free(data);
    return ret;
}

int init_key_bundle(KeyBundle* kb, uint32_t client_id, EVP_PKEY* private_key, const char* temp_user)
{
    if (!kb || !private_key)
    {
        return -1;
    }
    memset(kb, 0, sizeof(*kb));

    int ret = 0;

    EVP_PKEY* identity_pub_evp     = NULL;
    uint8_t*  identity_pub_der     = NULL;
    identity_pub_der               = NULL;
    EVP_PKEY*      vko_pub_evp     = NULL;
    uint16_t       vko_pub_len     = 0;
    uint8_t*       vko_pub_der     = NULL;
    uint8_t*       fingerprint     = NULL;
    uint16_t       fingerprint_len = 0;
    unsigned char* signature       = NULL;
    size_t         signature_len   = 0;

    kb->bundle_version = 1;
    kb->client_id      = client_id;
    char path[256];
    snprintf(path, sizeof(path), "./keys/%s/identity_public.pem", temp_user);
    pem_read_public_key(path, &identity_pub_evp);
    if (identity_pub_evp == NULL)
    {
        fprintf(stderr, "[ERROR] pem_read_public_key FAULTED");
        ret = -1;
        goto cleanup;
    }
    kb->identity_alg          = IKA_GOST2012_512;
    uint16_t identity_pub_len = 0;
    if (key_to_der_pub(identity_pub_evp, &identity_pub_der, &identity_pub_len) < 0)
    {
        fprintf(stderr, "[ERROR] key_to_der_pub  FAULTED");
        ret = -1;
        goto cleanup;
    }
    kb->identity_pub     = identity_pub_der;
    kb->identity_pub_len = identity_pub_len;
    identity_pub_der     = NULL;

    kb->vko_alg = VKO_GOST2012_512;
    snprintf(path, sizeof(path), "./keys/%s/vko_public.pem", temp_user);
    pem_read_public_key(path, &vko_pub_evp);
    if (vko_pub_evp == NULL)
    {
        fprintf(stderr, "[ERROR] pem_read_public_key FAULTED");
        ret = -1;
        goto cleanup;
    }
    if (key_to_der_pub(vko_pub_evp, &vko_pub_der, &vko_pub_len) < 0)
    {
        fprintf(stderr, "[ERROR] key_to_der_pub  FAULTED");
        ret = -1;
        goto cleanup;
    }
    kb->vko_pub_len    = vko_pub_len;
    kb->vko_pub        = vko_pub_der;
    vko_pub_der        = NULL;
    kb->vko_expires_at = (uint64_t)time(NULL) + VKO_TTL_SECONDS;

    kb->fingerprint_alg = FA_GOST2012_512;
    if (get_hash(FA_GOST2012_512, kb->identity_pub, kb->identity_pub_len, &fingerprint,
                 &fingerprint_len) < 0)
    {
        fprintf(stderr, "[ERROR] get_fingerprint FAULTED");
        ret = -1;
        goto cleanup;
    }
    kb->fingerprint_len = fingerprint_len;
    kb->fingerprint     = fingerprint;
    fingerprint         = NULL;

    kb->signature_alg = SigA_512;
    if (get_sign_kb(kb, private_key, &signature, &signature_len) < 0)
    {
        fprintf(stderr, "[ERROR] get_sign_kb FAULTED");
        ret = -1;
        goto cleanup;
    }
    if (signature_len > UINT16_MAX)
    {
        fprintf(stderr, "[ERROR] signature_len too large\n");
        ret = -1;
        goto cleanup;
    }
    kb->signature     = (uint8_t*)signature;
    signature         = NULL;
    kb->signature_len = (uint16_t)signature_len;

cleanup:

    EVP_PKEY_free(identity_pub_evp);
    OPENSSL_free(identity_pub_der);
    EVP_PKEY_free(vko_pub_evp);
    OPENSSL_free(vko_pub_der);

    if (ret < 0)
    {
        kb_clear(kb);
    }
    return ret;
}

int pem_write_private_key(const char* path, EVP_PKEY* key)
{
    int  ret = 0;
    BIO* bio = BIO_new_file(path, "w");
    if (!bio)
    {
        ossl_print_error("BIO_new_file failed");
        ret = -1;
        goto cleanup;
    }

    if (PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL) <= 0)
    {
        ossl_print_error("PEM_write_bio_PrivateKey failed");
        ret = -1;
        goto cleanup;
    }
cleanup:
    if (bio)
    {
        BIO_free(bio);
    }

    return ret;
}

int pem_write_public_key(const char* path, EVP_PKEY* key)
{
    int  ret = 0;
    BIO* bio = BIO_new_file(path, "w");
    if (!bio)
    {
        ossl_print_error("BIO_new_file failed");
        ret = -1;
        goto cleanup;
    }

    if (PEM_write_bio_PUBKEY(bio, key) <= 0)
    {
        ossl_print_error("PEM_write_bio_PUBKEY failed");
        ret = -1;
        goto cleanup;
    }
cleanup:
    if (bio)
    {
        BIO_free(bio);
    }

    return ret;
}

int pem_read_private_key(const char* path, EVP_PKEY** key)
{
    int  ret = -1;
    BIO* bio = BIO_new_file(path, "r");
    if (!bio)
    {
        ossl_print_error("BIO_new_file failed");
        goto cleanup;
    }

    if (!PEM_read_bio_PrivateKey(bio, key, NULL, NULL))
    {
        ossl_print_error("PEM_read_bio_PrivateKey failed");
        goto cleanup;
    }
    ret = 0;
cleanup:
    if (bio)
    {
        BIO_free(bio);
    }

    return ret;
}

int pem_read_public_key(const char* path, EVP_PKEY** key)
{
    int  ret = 0;
    BIO* bio = BIO_new_file(path, "r");
    if (!bio)
    {
        ossl_print_error("BIO_new_file failed");
        ret = -1;
        goto cleanup;
    }

    if (!PEM_read_bio_PUBKEY(bio, key, NULL, NULL))
    {
        ossl_print_error("PEM_read_bio_PUBKEY failed");
        ret = -1;
        goto cleanup;
    }
cleanup:
    if (bio)
    {
        BIO_free(bio);
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

int der_write_private_key(const char* path, EVP_PKEY* key)
{
    int  ret = 0;
    BIO* bio = BIO_new_file(path, "wb");
    if (!bio)
    {
        ossl_print_error("BIO_new_file failed");
        ret = -1;
        goto cleanup;
    }
    if (i2d_PrivateKey_bio(bio, key) <= 0)
    {
        ossl_print_error("i2d_PrivateKey_bio failed");
        ret = -1;
        goto cleanup;
    }
cleanup:
    if (bio)
    {
        BIO_free(bio);
    }

    return ret;
}

int der_read_public_key(const char* path, EVP_PKEY** key)
{
    int  ret = 0;
    BIO* bio = BIO_new_file(path, "rb");
    if (!bio)
    {
        ossl_print_error("BIO_new_file failed");
        ret = -1;
        goto cleanup;
    }

    if (!d2i_PUBKEY_bio(bio, key))
    {
        ossl_print_error("d2i_PUBKEY_bio failed");
        ret = -1;
        goto cleanup;
    }
cleanup:
    if (bio)
    {
        BIO_free(bio);
    }

    return ret;
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

int serialize_key_bundle_to_sign(KeyBundle* kb, uint8_t** out, uint16_t* out_len)
{
    if (!kb || !out || !out_len)
    {
        return -1;
    }

    int ret = -1;

    uint8_t* buf = NULL;
    size_t   len = 0;
    *out         = NULL;
    *out_len     = 0;

    len += 1; // bundle version
    len += 4; // client_id

    len += 1;                    // identity_alg
    len += 2;                    // identity_pub_len
    len += kb->identity_pub_len; // identity_pub

    len += 1;               // vko_alg
    len += 2;               // vko_pub_len
    len += kb->vko_pub_len; // vko_pub
    len += 8;               // vko_expires_at

    len += 1; // fingerprint_alg
    len += 2; // fingerprint_len
    len += kb->fingerprint_len;

    len += 1; // signature_alg

    if (len > UINT16_MAX)
    {
        fprintf(stderr, "serialized bundle too large\n");
        goto cleanup;
    }
    buf = OPENSSL_malloc(len);
    if (!buf)
    {
        ossl_print_error("OPENSSL_malloc failed");
        goto cleanup;
    }
    uint8_t* p = buf;
    *p++       = (uint8_t)kb->bundle_version;

    put_u32_be(p, kb->client_id);
    p += 4;

    // identity
    if (!kb->identity_pub || kb->identity_pub_len == 0)
    {
        fprintf(stderr, "identity_pub bad\n");
        goto cleanup;
    }

    *p++ = (uint8_t)kb->identity_alg;

    put_u16_be(p, kb->identity_pub_len);
    p += 2;

    memcpy(p, kb->identity_pub, kb->identity_pub_len);
    p += kb->identity_pub_len;

    // vko
    if (!kb->vko_pub || kb->vko_pub_len <= 0)
    {
        fprintf(stderr, "vko_pub bad\n");
        goto cleanup;
    }

    *p++ = (uint8_t)kb->vko_alg;

    put_u16_be(p, kb->vko_pub_len);
    p += 2;

    memcpy(p, kb->vko_pub, kb->vko_pub_len);
    p += kb->vko_pub_len;

    put_u64_be(p, kb->vko_expires_at);
    p += 8;

    // fingerprint
    if (!kb->fingerprint || kb->fingerprint_len == 0)
    {
        fprintf(stderr, "fingerprint bad\n");
        goto cleanup;
    }

    *p++ = (uint8_t)kb->fingerprint_alg;

    put_u16_be(p, kb->fingerprint_len);
    p += 2;

    memcpy(p, kb->fingerprint, kb->fingerprint_len);
    p += kb->fingerprint_len;

    // signature
    *p++ = (uint8_t)kb->signature_alg;

    if ((size_t)(p - buf) != len)
    {
        fprintf(stderr, "serialized buf len mismatch\n");
        goto cleanup;
    }
    *out     = buf;
    *out_len = (uint16_t)len;
    buf      = NULL;
    p        = NULL;

    ret = 0;
cleanup:
    OPENSSL_free(buf);
    return ret;
}

int serialize_key_bundle_full(KeyBundle* kb, uint8_t** out, uint16_t* out_len)
{
    if (!kb || !out || !out_len)
    {
        return -1;
    }

    int ret = -1;

    uint8_t* buf = NULL;
    size_t   len = 0;
    *out         = NULL;
    *out_len     = 0;

    len += 1; // bundle version
    len += 4; // client_id

    len += 1;                    // identity_alg
    len += 2;                    // identity_pub_len
    len += kb->identity_pub_len; // identity_pub

    len += 1;               // vko_alg
    len += 2;               // vko_pub_len
    len += kb->vko_pub_len; // vko_pub
    len += 8;               // vko_expires_at

    len += 1; // fingerprint_alg
    len += 2; // fingerprint_len
    len += kb->fingerprint_len;

    len += 1; // signature_alg
    len += 2; // signature_len
    len += kb->signature_len;

    if (len > UINT16_MAX)
    {
        fprintf(stderr, "serialized bundle too large\n");
        goto cleanup;
    }
    buf = OPENSSL_malloc(len);
    if (!buf)
    {
        ossl_print_error("OPENSSL_malloc failed");
        goto cleanup;
    }
    uint8_t* p = buf;
    *p++       = (uint8_t)kb->bundle_version;

    put_u32_be(p, kb->client_id);
    p += 4;

    // identity
    if (!kb->identity_pub || kb->identity_pub_len == 0)
    {
        fprintf(stderr, "identity_pub bad\n");
        goto cleanup;
    }

    *p++ = (uint8_t)kb->identity_alg;

    put_u16_be(p, kb->identity_pub_len);
    p += 2;

    memcpy(p, kb->identity_pub, kb->identity_pub_len);
    p += kb->identity_pub_len;

    // vko
    if (!kb->vko_pub || kb->vko_pub_len <= 0)
    {
        fprintf(stderr, "vko_pub bad\n");
        goto cleanup;
    }

    *p++ = (uint8_t)kb->vko_alg;

    put_u16_be(p, kb->vko_pub_len);
    p += 2;

    memcpy(p, kb->vko_pub, kb->vko_pub_len);
    p += kb->vko_pub_len;

    put_u64_be(p, kb->vko_expires_at);
    p += 8;

    // fingerprint
    if (!kb->fingerprint || kb->fingerprint_len == 0)
    {
        fprintf(stderr, "fingerprint bad\n");
        goto cleanup;
    }

    *p++ = (uint8_t)kb->fingerprint_alg;

    put_u16_be(p, kb->fingerprint_len);
    p += 2;

    memcpy(p, kb->fingerprint, kb->fingerprint_len);
    p += kb->fingerprint_len;

    // signature
    if (!kb->signature || kb->signature_len == 0)
    {
        fprintf(stderr, "signature bad\n");
        goto cleanup;
    }

    *p++ = (uint8_t)kb->signature_alg;

    put_u16_be(p, kb->signature_len);
    p += 2;

    memcpy(p, kb->signature, kb->signature_len);
    p += kb->signature_len;

    if ((size_t)(p - buf) != len)
    {
        fprintf(stderr, "serialized buf len mismatch\n");
        goto cleanup;
    }
    *out     = buf;
    *out_len = (uint16_t)len;
    buf      = NULL;
    p        = NULL;

    ret = 0;
cleanup:
    OPENSSL_free(buf);
    return ret;
}

KeyBundle* deserialize_key_bundle_full(const uint8_t* data, uint16_t data_len)
{
    KeyBundle* kb = calloc(1, sizeof(KeyBundle));
    if (!kb)
    {
        return NULL;
    }
    KeyBundle* ret = NULL;

    const uint8_t* p   = data;
    const uint8_t* end = data + data_len;
#define NEED(x)                                                                                    \
    do                                                                                             \
    {                                                                                              \
        if ((size_t)(end - p) < (size_t)(x))                                                       \
        {                                                                                          \
            goto cleanup;                                                                          \
        }                                                                                          \
    } while (0)

    NEED(1);
    kb->bundle_version = *p++;

    NEED(4);
    kb->client_id = get_u32_be(p);
    p += 4;

    // identity
    NEED(1);
    kb->identity_alg = *p++;

    NEED(2);
    kb->identity_pub_len = get_u16_be(p);
    p += 2;

    if (kb->identity_pub_len == 0)
    {
        fprintf(stderr, "identity_pub_len bad\n");
        goto cleanup;
    }

    NEED(kb->identity_pub_len);
    kb->identity_pub = OPENSSL_malloc(kb->identity_pub_len);
    if (!kb->identity_pub)
    {
        fprintf(stderr, "identity_pub bad\n");
        goto cleanup;
    }
    memcpy(kb->identity_pub, p, kb->identity_pub_len);
    p += kb->identity_pub_len;

    // vko
    NEED(1);
    kb->vko_alg = (uint8_t)*p++;

    NEED(2);
    kb->vko_pub_len = get_u16_be(p);
    p += 2;

    if (kb->vko_pub_len == 0)
    {
        fprintf(stderr, "vko_pub_len bad\n");
        goto cleanup;
    }

    NEED(kb->vko_pub_len);
    kb->vko_pub = OPENSSL_malloc(kb->vko_pub_len);
    if (!kb->vko_pub)
    {
        fprintf(stderr, "vko_pub bad\n");
        goto cleanup;
    }
    memcpy(kb->vko_pub, p, kb->vko_pub_len);
    p += kb->vko_pub_len;

    NEED(8);
    kb->vko_expires_at = get_u64_be(p);
    p += 8;

    // fingerprint
    NEED(1);
    kb->fingerprint_alg = *p++;

    NEED(2);
    kb->fingerprint_len = get_u16_be(p);
    p += 2;
    if (kb->fingerprint_len == 0)
    {
        fprintf(stderr, "fingerprint_len bad\n");
        goto cleanup;
    }

    NEED(kb->fingerprint_len);
    kb->fingerprint = OPENSSL_malloc(kb->fingerprint_len);
    if (!kb->fingerprint)
    {
        fprintf(stderr, "fingerprint bad\n");
        goto cleanup;
    }
    memcpy(kb->fingerprint, p, kb->fingerprint_len);
    p += kb->fingerprint_len;

    // signature
    NEED(1);
    kb->signature_alg = *p++;

    NEED(2);
    kb->signature_len = get_u16_be(p);
    p += 2;

    if (kb->signature_len == 0)
    {
        fprintf(stderr, "signature_len bad\n");
        goto cleanup;
    }

    NEED(kb->signature_len);
    kb->signature = OPENSSL_malloc(kb->signature_len);
    if (!kb->signature)
    {
        ossl_print_error("OPENSSL_malloc failed");
        goto cleanup;
    }
    memcpy(kb->signature, p, kb->signature_len);
    p += kb->signature_len;

    if (p != end)
    {
        fprintf(stderr, "extra bytes in bundle\n");
        goto cleanup;
    }

    ret = kb;
cleanup:
    if (!ret)
    {
        kb_free(kb);
    }

    return ret;
}

int verify_key_bundle(const uint8_t* data, uint16_t data_len)
{
    if (!data)
    {
        return -1;
    }

    int        ret        = -1;
    KeyBundle* kb         = NULL;
    EVP_PKEY*  public_key = NULL;
    uint8_t*   hash       = NULL;
    uint16_t   hash_len   = 0;

    // 1. deserialize_key_bundle_full
    kb = deserialize_key_bundle_full(data, data_len);
    if (!kb)
    {
        fprintf(stderr, "deserialize_key_bundle_full failed\n");
        goto cleanup;
    }
    // 2. проверить bundle_version
    if (kb->bundle_version != 1)
    {
        fprintf(stderr, "wrong bundle version\n");
        goto cleanup;
    }
    // 3. проверить identity_alg, vko_alg, fingerprint_alg, signature_alg
    if (validate_key_bundle_algorithms(kb) < 0)
    {
        fprintf(stderr, "wrong key bundle algorithms\n");
        goto cleanup;
    }
    // 4. проверить vko_expires_at > time(NULL)
    if (kb->vko_expires_at <= (uint64_t)time(NULL))
    {
        fprintf(stderr, "vko expired\n");
        goto cleanup;
    }
    // 5. пересчитать fingerprint от identity_pub
    if (get_hash(kb->fingerprint_alg, kb->identity_pub, kb->identity_pub_len, &hash, &hash_len) < 0)
    {
        fprintf(stderr, "fingerprint: get_hash failed\n");
        goto cleanup;
    }
    if (kb->fingerprint_len != hash_len)
    {
        fprintf(stderr, "fingerprint len mismatch\n");
        goto cleanup;
    }
    // 6. сравнить с kb->fingerprint
    if (memcmp(kb->fingerprint, hash, kb->fingerprint_len) != 0)
    {
        fprintf(stderr, "fingerprint is wrong\n");
        goto cleanup;
    }
    // // 7. найти name в keystore
    // int idx = find_in_key_store(items, items_len, name);
    // if (idx < 0)
    // {
    //     goto cleanup;
    // }
    // // 8. сравнить identity_pub из bundle с identity_pub из keystore
    // if (items[idx].pubkey_len != kb->identity_pub_len ||
    //     memcmp(items[idx].pubkey, kb->identity_pub, kb->identity_pub_len) != 0)
    // {
    //     fprintf(stderr, "pubkey is wrong for this name\n");
    //     goto cleanup;
    // }

    // 9. der_to_key_pub(identity_pub)
    if (der_to_key_pub(&public_key, kb->identity_pub, kb->identity_pub_len) < 0)
    {
        fprintf(stderr, "der_to_key_pub failed\n");
        goto cleanup;
    }
    if (!public_key)
    {
        fprintf(stderr, "der_to_key_pub failed\n");
        goto cleanup;
    }
    // 10. verify_sign(kb, identity_pub_key)
    ret = verify_sign(kb, public_key);
cleanup:
    if (kb)
    {
        kb_free(kb);
    }
    EVP_PKEY_free(public_key);
    OPENSSL_free(hash);
    return ret;
}

int validate_key_bundle_algorithms(KeyBundle* kb)
{
    if (kb->vko_alg != VKO_GOST2012_512)
    {
        return -1;
    }
    if (kb->identity_alg != IKA_GOST2012_512)
    {
        return -1;
    }
    if (kb->signature_alg != SigA_512)
    {
        return -1;
    }
    if (kb->fingerprint_alg != FA_GOST2012_512)
    {
        return -1;
    }
    return 0;
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

// KDF_GOSTR3411_2012_256(K_in, label, seed)
// =
// HMAC_GOSTR3411_2012_256(
//     K_in,
//     0x01 || label || 0x00 || seed || 0x01 || 0x00
// )

int get_kdf(uint8_t* secret_key, uint16_t secret_key_len, const uint8_t* salt, uint16_t salt_len,
            uint8_t* info, uint16_t info_len, uint8_t* key, size_t keylen)
{
    if (!secret_key || (!salt && salt_len != 0) || !info || !key)
    {
        return -1;
    }
    if (keylen != 32)
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

    if (EVP_KDF_derive(ctx, key, keylen, params) != 1)
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

// 1. Из wrapping_key вывести два ключа:
//    enc_key
//    mac_key

// 2. Зашифровать room_key:
//    encrypted_room_key = Kuznyechik-CTR(enc_key, nonce, room_key)

// 3. Посчитать MAC:
//    tag = Kuznyechik-MAC(mac_key,
//        aad || nonce || encrypted_room_key
//    )

// AAD:
//     packet_type = PKT_ENC_ROOM_KEY
//     sender_id
//     to_client_id
//     room_id
//     epoch

// PLAINTEXT:
//     room_key

// OUTPUT:
//     encrypted_room_key
//     tag
int kuznechik_encrypt_room_key(uint8_t* nonce, uint8_t* enc_key, uint8_t* room_key,
                               int room_key_len, uint8_t* mac_key, uint8_t aad[AAD_LEN],
                               uint8_t** out, uint16_t* out_len, uint8_t** tag_out,
                               uint16_t* tag_out_len)
{
    if (!nonce || !enc_key || !room_key || !mac_key || room_key_len != 32)
    {
        return -1;
    }

    int             ret                    = -1;
    EVP_CIPHER*     cipher                 = NULL;
    EVP_CIPHER_CTX* ctx                    = NULL;
    uint8_t*        encrypted_room_key     = NULL;
    int             encrypted_room_key_len = 0;
    int             outl                   = 0;
    EVP_MAC*        mac                    = NULL;
    EVP_MAC_CTX*    mctx                   = NULL;
    uint8_t*        tag                    = NULL;

    cipher = EVP_CIPHER_fetch(NULL, "kuznyechik-ctr-acpkm", NULL);
    if (!cipher)
    {
        ossl_print_error("EVP_CIPHER_fetch");
        goto cleanup;
    }
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        ossl_print_error("EVP_CIPHER_CTX_new");
        goto cleanup;
    }
    if (EVP_EncryptInit_ex2(ctx, cipher, enc_key, nonce, NULL) != 1)
    {
        ossl_print_error("EVP_EncryptInit_ex2");
        goto cleanup;
    }
    encrypted_room_key = OPENSSL_malloc(32);
    if (!encrypted_room_key)
    {
        ossl_print_error("encrypted_room_key");
        goto cleanup;
    }
    if (EVP_EncryptUpdate(ctx, encrypted_room_key, &outl, room_key, room_key_len) != 1)
    {
        ossl_print_error("EVP_EncryptUpdate");
        goto cleanup;
    }
    encrypted_room_key_len += outl;
    if (EVP_EncryptFinal_ex(ctx, encrypted_room_key + encrypted_room_key_len, &outl) != 1)
    {
        ossl_print_error("EVP_EncryptFinal_ex");
        goto cleanup;
    }
    encrypted_room_key_len += outl;

    mac = EVP_MAC_fetch(NULL, "kuznyechik-mac", NULL);
    if (!mac)
    {
        ossl_print_error("EVP_MAC_fetch");
        goto cleanup;
    }
    mctx = EVP_MAC_CTX_new(mac);
    if (!mctx)
    {
        ossl_print_error("EVP_MAC_CTX_new");
        goto cleanup;
    }
    if (EVP_MAC_init(mctx, mac_key, 32, NULL) != 1)
    {
        ossl_print_error("EVP_MAC_init");
        goto cleanup;
    }

    if (EVP_MAC_update(mctx, aad, AAD_LEN) != 1)
    {
        ossl_print_error("EVP_MAC_update");
        goto cleanup;
    }
    if (EVP_MAC_update(mctx, nonce, PKT_ENC_ROOM_KEY_NONCE_LEN) != 1)
    {
        ossl_print_error("EVP_MAC_update");
        goto cleanup;
    }
    if (EVP_MAC_update(mctx, encrypted_room_key, encrypted_room_key_len) != 1)
    {
        ossl_print_error("EVP_MAC_update");
        goto cleanup;
    }

    tag = OPENSSL_malloc(PKT_ENC_ROOM_KEY_TAG_LEN);
    if (!tag)
    {
        ossl_print_error("OPENSSL_malloc");
        goto cleanup;
    }
    size_t mac_len  = 0;
    size_t mac_outl = 0;
    if (EVP_MAC_final(mctx, tag, &mac_outl, PKT_ENC_ROOM_KEY_TAG_LEN) != 1)
    {
        ossl_print_error("EVP_MAC_final");
        goto cleanup;
    }
    mac_len += mac_outl;
    if (mac_len != PKT_ENC_ROOM_KEY_TAG_LEN)
    {
        fprintf(stderr, "invalid mac_len: %zu\n", mac_len);
        goto cleanup;
    }

    *out = encrypted_room_key;
    if (out_len)
    {
        *out_len = encrypted_room_key_len;
    }
    encrypted_room_key = NULL;
    *tag_out           = tag;
    tag                = NULL;

    if (tag_out_len)
    {
        *tag_out_len = (uint16_t)mac_len;
    }

    ret = 0;
cleanup:
    OPENSSL_free(encrypted_room_key);
    OPENSSL_free(tag);
    EVP_CIPHER_free(cipher);
    cipher = NULL;
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;
    EVP_MAC_CTX_free(mctx);
    mctx = NULL;
    EVP_MAC_free(mac);
    mac = NULL;

    return ret;
}

int kuznechik_decrypt_room_key(uint8_t* nonce, uint8_t* enc_key, uint8_t* encrypted_room_key,
                               int encrypted_room_key_len, uint8_t* mac_key, uint8_t aad[AAD_LEN],
                               uint8_t** out, uint16_t* out_len, uint8_t* tag_in,
                               uint16_t tag_in_len)
{
    if (!nonce || !enc_key || !encrypted_room_key || !mac_key || encrypted_room_key_len != 32 ||
        !out || !tag_in || !out_len)
    {
        return -1;
    }

    int             ret                    = -1;
    EVP_CIPHER*     cipher                 = NULL;
    EVP_CIPHER_CTX* ctx                    = NULL;
    uint8_t*        decrypted_room_key     = NULL;
    int             decrypted_room_key_len = 0;
    int             outl                   = 0;
    EVP_MAC*        mac                    = NULL;
    EVP_MAC_CTX*    mctx                   = NULL;
    uint8_t*        tag                    = NULL;

    mac = EVP_MAC_fetch(NULL, "kuznyechik-mac", NULL);
    if (!mac)
    {
        ossl_print_error("EVP_MAC_fetch");
        goto cleanup;
    }
    mctx = EVP_MAC_CTX_new(mac);
    if (!mctx)
    {
        ossl_print_error("EVP_MAC_CTX_new");
        goto cleanup;
    }
    if (EVP_MAC_init(mctx, mac_key, 32, NULL) != 1)
    {
        ossl_print_error("EVP_MAC_init");
        goto cleanup;
    }

    if (EVP_MAC_update(mctx, aad, AAD_LEN) != 1)
    {
        ossl_print_error("EVP_MAC_update");
        goto cleanup;
    }
    if (EVP_MAC_update(mctx, nonce, PKT_ENC_ROOM_KEY_NONCE_LEN) != 1)
    {
        ossl_print_error("EVP_MAC_update");
        goto cleanup;
    }
    if (EVP_MAC_update(mctx, encrypted_room_key, encrypted_room_key_len) != 1)
    {
        ossl_print_error("EVP_MAC_update");
        goto cleanup;
    }

    tag = OPENSSL_malloc(PKT_ENC_ROOM_KEY_TAG_LEN);
    if (!tag)
    {
        ossl_print_error("OPENSSL_malloc");
        goto cleanup;
    }
    size_t mac_len  = 0;
    size_t mac_outl = 0;
    if (EVP_MAC_final(mctx, tag, &mac_outl, PKT_ENC_ROOM_KEY_TAG_LEN) != 1)
    {
        ossl_print_error("EVP_MAC_final");
        goto cleanup;
    }
    mac_len += mac_outl;
    if (mac_len != PKT_ENC_ROOM_KEY_TAG_LEN || tag_in_len != PKT_ENC_ROOM_KEY_TAG_LEN)
    {
        fprintf(stderr, "invalid mac_len: %zu\n", mac_len);
        goto cleanup;
    }
    if (CRYPTO_memcmp(tag, tag_in, tag_in_len) != 0)
    {
        fprintf(stderr, "invalid tag\n");
        goto cleanup;
    }

    cipher = EVP_CIPHER_fetch(NULL, "kuznyechik-ctr-acpkm", NULL);
    if (!cipher)
    {
        ossl_print_error("EVP_CIPHER_fetch");
        goto cleanup;
    }
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        ossl_print_error("EVP_CIPHER_CTX_new");
        goto cleanup;
    }
    if (EVP_DecryptInit_ex2(ctx, cipher, enc_key, nonce, NULL) != 1)
    {
        ossl_print_error("EVP_EncryptInit_ex2");
        goto cleanup;
    }
    decrypted_room_key = OPENSSL_malloc(32);
    if (!decrypted_room_key)
    {
        ossl_print_error("encrypted_room_key");
        goto cleanup;
    }
    if (EVP_DecryptUpdate(ctx, decrypted_room_key, &outl, encrypted_room_key,
                          encrypted_room_key_len) != 1)
    {
        ossl_print_error("EVP_EncryptUpdate");
        goto cleanup;
    }
    decrypted_room_key_len += outl;
    if (EVP_DecryptFinal_ex(ctx, decrypted_room_key + decrypted_room_key_len, &outl) != 1)
    {
        ossl_print_error("EVP_EncryptFinal_ex");
        goto cleanup;
    }
    decrypted_room_key_len += outl;
    if (decrypted_room_key_len != ROOM_KEY_LEN)
    {
        fprintf(stderr, "decrypted_room_key_len mismatch\n");
        goto cleanup;
    }

    *out = decrypted_room_key;
    if (out_len)
    {
        *out_len = decrypted_room_key_len;
    }
    decrypted_room_key = NULL;

    ret = 0;
cleanup:
    OPENSSL_clear_free(decrypted_room_key, ROOM_KEY_LEN);
    OPENSSL_free(tag);
    EVP_CIPHER_free(cipher);
    cipher = NULL;
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;
    EVP_MAC_CTX_free(mctx);
    mctx = NULL;
    EVP_MAC_free(mac);
    mac = NULL;

    return ret;
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

// [1 packet_type]
// [1 enc_version]
// [1 suite]
// [2 reserved]
// [4 sender_id]
// [4 room_id]
// [8 room_epoch]
// [8 seq]
static int build_aad_for_enc_chat(uint8_t  aad_for_enc_chat[AAD_FOR_ENC_CHAT_LEN],
                                  uint32_t sender_id, uint32_t room_id, uint64_t epoch,
                                  uint64_t seq)
{
    if (!aad_for_enc_chat)
    {
        return -1;
    }
    size_t   off = 0;
    uint8_t* p   = aad_for_enc_chat;

    // [1 packet_type]
    *(p + off) = PKT_ENC_CHAT;
    off++;

    // [1 enc_version]
    *(p + off) = 1;
    off++;

    // [1 suite]
    *(p + off) = 1;
    off++;

    // [2 reserved]
    *(p + off) = 0;
    off++;
    *(p + off) = 0;
    off++;

    // [4 sender_id]
    put_u32_be(p + off, sender_id);
    off += sizeof(sender_id);

    // [4 room_id]
    put_u32_be(p + off, room_id);
    off += sizeof(room_id);

    // [8 room_epoch]
    put_u64_be(p + off, epoch);
    off += sizeof(epoch);

    // [8 seq]
    put_u64_be(p + off, seq);
    off += sizeof(seq);

    if (off != AAD_FOR_ENC_CHAT_LEN)
    {
        return -1;
    }
    return 0;
}

static int encrypt_chat_message(uint8_t room_key[ROOM_KEY_LEN], uint32_t sender_id,
                                uint32_t room_id, uint64_t epoch, uint64_t send_seq, uint8_t* msg,
                                uint16_t msg_len, uint8_t** out_msg, uint16_t* out_msg_len,
                                uint8_t** out_tag, uint16_t* out_tag_len, uint8_t** out_nonce)
{
    if (!room_key || !msg || !out_msg || !out_tag || !out_msg_len || !out_tag_len || !out_nonce)
    {
        return -1;
    }

    uint8_t* cipher     = NULL;
    uint16_t cipher_len = 0;
    uint8_t* tag        = NULL;
    uint16_t tag_len    = 0;
    size_t   off        = 0;
    int      ret        = -1;
    // sender_id: 4 байта
    // seq:       8 байт
    // random32:  4 байта
    uint8_t* nonce = OPENSSL_malloc(ENC_NONCE);
    if (!nonce)
    {
        ossl_print_error("OPENSSL_malloc");
        goto cleanup;
    }
    // sender_id: 4 байта
    put_u32_be(nonce + off, sender_id);
    off += sizeof(sender_id);
    // seq:       8 байт
    put_u64_be(nonce + off, send_seq);
    off += sizeof(send_seq);
    // random32:  4 байта
    if (RAND_bytes(nonce + off, 4) != 1)
    {
        ossl_print_error("RAND_bytes");
        goto cleanup;
    }
    off += 4;
    if (off != ENC_NONCE)
    {
        fprintf(stderr, "NONCE len mismatch");
        goto cleanup;
    }

    uint8_t mac_key[32];
    uint8_t enc_key[32];

    uint8_t aad[AAD_FOR_ENC_CHAT_LEN];
    if (build_aad_for_enc_chat(aad, sender_id, room_id, epoch, send_seq))
    {
        fprintf(stderr, "build_aad_for_enc_chat failed\n");
        goto cleanup;
    }
    const unsigned char salt_enc[] = "enc-chat enc";
    if (get_kdf(room_key, ROOM_KEY_LEN, salt_enc, (uint16_t)(sizeof(salt_enc) - 1), aad,
                AAD_FOR_ENC_CHAT_LEN, enc_key, 32) < 0)
    {
        fprintf(stderr, "get_kdf failed\n");
        goto cleanup;
    }
    const unsigned char salt_mac[] = "enc-chat mac";
    if (get_kdf(room_key, ROOM_KEY_LEN, salt_mac, (uint16_t)(sizeof(salt_mac) - 1), aad,
                AAD_FOR_ENC_CHAT_LEN, mac_key, 32) < 0)
    {
        fprintf(stderr, "get_kdf failed\n");
        goto cleanup;
    }
    if (kuznechik_encrypt_message(nonce, enc_key, msg, msg_len, mac_key, aad, &cipher, &cipher_len,
                                  &tag, &tag_len) < 0 ||
        !cipher || !tag)
    {
        fprintf(stderr, "kuznechik_encrypt_message failed\n");
        goto cleanup;
    }
    if (cipher_len > ENC_PLAINTEXT_MAX_LEN)
    {
        fprintf(stderr, "cipher_len too large\n");
        goto cleanup;
    }
    if (tag_len != ENC_TAG)
    {
        fprintf(stderr, "cipher_len mismatch\n");
        goto cleanup;
    }

    *out_msg     = cipher;
    *out_msg_len = cipher_len;
    *out_tag     = tag;
    *out_tag_len = tag_len;
    *out_nonce   = nonce;
    cipher       = NULL;
    tag          = NULL;
    nonce        = NULL;
    ret          = 0;
cleanup:
    OPENSSL_free(nonce);
    OPENSSL_free(cipher);
    OPENSSL_free(tag);
    OPENSSL_cleanse(mac_key, sizeof mac_key);
    OPENSSL_cleanse(enc_key, sizeof enc_key);
    return ret;
}

int decrypt_chat_message(uint8_t* nonce, uint8_t room_key[ROOM_KEY_LEN], uint32_t sender_id,
                         uint32_t room_id, uint64_t epoch, uint64_t seq, uint8_t* msg,
                         uint16_t msg_len, uint8_t* tag, uint8_t** out_msg, uint16_t* out_msg_len)
{
    if (!nonce || !room_key || !msg || !out_msg || !out_msg_len || !tag)
    {
        return -1;
    }

    uint8_t* cipher     = NULL;
    uint16_t cipher_len = 0;
    int      ret        = -1;
    uint8_t  mac_key[32];
    uint8_t  enc_key[32];

    uint8_t aad[AAD_FOR_ENC_CHAT_LEN];
    if (build_aad_for_enc_chat(aad, sender_id, room_id, epoch, seq))
    {
        fprintf(stderr, "build_aad_for_enc_chat failed\n");
        goto cleanup;
    }
    const unsigned char salt_enc[] = "enc-chat enc";
    if (get_kdf(room_key, ROOM_KEY_LEN, salt_enc, (uint16_t)(sizeof(salt_enc) - 1), aad,
                AAD_FOR_ENC_CHAT_LEN, enc_key, 32) < 0)
    {
        fprintf(stderr, "get_kdf failed\n");
        goto cleanup;
    }
    const unsigned char salt_mac[] = "enc-chat mac";
    if (get_kdf(room_key, ROOM_KEY_LEN, salt_mac, (uint16_t)(sizeof(salt_mac) - 1), aad,
                AAD_FOR_ENC_CHAT_LEN, mac_key, 32) < 0)
    {
        fprintf(stderr, "get_kdf failed\n");
        goto cleanup;
    }
    if (kuznechik_decrypt_message(nonce, enc_key, msg, msg_len, mac_key, aad, &cipher, &cipher_len,
                                  tag, ENC_TAG) < 0 ||
        !cipher)
    {
        fprintf(stderr, "kuznechik_decrypt_message failed\n");
        goto cleanup;
    }
    if (cipher_len > ENC_PLAINTEXT_MAX_LEN)
    {
        fprintf(stderr, "cipher_len too large\n");
        goto cleanup;
    }

    *out_msg     = cipher;
    *out_msg_len = cipher_len;
    cipher       = NULL;
    ret          = 0;
cleanup:
    if (ret != 0)
    {
        *out_msg     = NULL;
        *out_msg_len = 0;
    }

    OPENSSL_free(cipher);
    OPENSSL_cleanse(mac_key, sizeof mac_key);
    OPENSSL_cleanse(enc_key, sizeof enc_key);
    return ret;
}

// PKT_ENC_CHAT
// [1  enc_version]
// [1  suite]
// [2  reserved]
// [8  room_epoch]
// [8  seq]
// [16 nonce]
// [N  ciphertext]
// [16 tag]
int client_send_pkt_enc_chat(int epfd, Client* c, RoomSession* room, uint8_t* msg, uint16_t msg_len)
{
    if (!c || !room || !msg || msg_len > ENC_PLAINTEXT_MAX_LEN)
    {
        return -1;
    }
    int    ret            = -1;
    Header h              = {0};
    h.flags               = 0;
    h.message_id          = 0;
    h.room_id             = room->room_id;
    h.sender_id           = c->id;
    h.type                = PKT_ENC_CHAT;
    h.version             = 1;
    h.timestamp           = (uint64_t)time(NULL);
    uint8_t* enc_msg      = NULL;
    uint16_t enc_msg_len  = 0;
    uint8_t* tag          = NULL;
    uint16_t tag_len      = 0;
    uint8_t* pkt_enc_chat = NULL;
    uint8_t* p            = NULL;
    uint8_t* nonce        = NULL;

    if (encrypt_chat_message(room->room_key, c->id, c->room_id, room->epoch, room->send_seq, msg,
                             msg_len, &enc_msg, &enc_msg_len, &tag, &tag_len, &nonce) < 0)
    {
        fprintf(stderr, "encrypt_chat_message failed\n");
        goto cleanup;
    }
    if (enc_msg_len > ENC_PLAINTEXT_MAX_LEN)
    {
        fprintf(stderr, "enc_msg_len too large\n");
        goto cleanup;
    }
    pkt_enc_chat = OPENSSL_malloc(ENC_OVERHEAD + enc_msg_len);
    if (!pkt_enc_chat)
    {
        ossl_print_error("OPENSSL_malloc");
        goto cleanup;
    }
    p = pkt_enc_chat;

    // [1  enc_version]
    *p++ = 1;
    // [1  suite]
    *p++ = 1;
    // [2  reserved]
    *p++ = 0;
    *p++ = 0;
    // [8  room_epoch]
    put_u64_be(p, room->epoch);
    p += 8;
    // [8  seq]
    put_u64_be(p, room->send_seq);
    p += 8;
    // [16 nonce]
    memcpy(p, nonce, ENC_NONCE);
    p += ENC_NONCE;
    // [N  ciphertext]
    memcpy(p, enc_msg, enc_msg_len);
    p += enc_msg_len;
    // [16 tag]
    if (tag_len != ENC_TAG)
    {
        fprintf(stderr, "WRONG tag_len\n");
        goto cleanup;
    }
    memcpy(p, tag, tag_len);
    p += tag_len;

    if ((uint16_t)(p - pkt_enc_chat) != ENC_OVERHEAD + enc_msg_len)
    {
        fprintf(stderr, "WRONG pkt_enc_chat len");
        goto cleanup;
    }

    size_t pkt_enc_chat_len = ENC_OVERHEAD + enc_msg_len;

    if (enqueue_packet(c, &h, pkt_enc_chat, pkt_enc_chat_len) < 0)
    {
        fprintf(stderr, "enqueue_packet failed\n");
        goto cleanup;
    }
    if (set_epollout_to_client(epfd, c) < 0)
    {
        fprintf(stderr, "set_epollout_to_client failed\n");
        goto cleanup;
    }
    room->send_seq++;
    ret = 0;
cleanup:
    OPENSSL_free(enc_msg);
    OPENSSL_free(tag);
    OPENSSL_free(nonce);
    OPENSSL_free(pkt_enc_chat);
    return ret;
}

// PKT_ENC_CHAT
// [1  enc_version]
// [1  suite]
// [2  reserved]
// [8  room_epoch]
// [8  seq]
// [16 nonce]
// [N  ciphertext]
// [16 tag]
int client_recv_pkt_enc_chat(Client* c, Header* h, RoomSession* room, uint8_t* msg,
                             uint16_t msg_len, uint8_t** out_msg, uint16_t* out_msg_len)
{
    if (!c || !h || !room || !msg || !out_msg || msg_len < ENC_OVERHEAD || msg_len > PAYLOAD_SIZE)
    {
        return -1;
    }
    int      ret         = -1;
    uint8_t* p           = NULL;
    size_t   off         = 0;
    p                    = msg;
    uint8_t  enc_version = 0;
    uint8_t  suite       = 0;
    uint64_t room_epoch  = 0;
    uint64_t seq         = 0;
    uint8_t  nonce[ENC_NONCE];
    memset(nonce, 0, ENC_NONCE);
    uint8_t* ciphertext     = NULL;
    uint16_t ciphertext_len = msg_len - ENC_OVERHEAD;
    uint8_t* tag            = NULL;
    uint16_t tag_len        = ENC_TAG;
    *out_msg                = NULL;
    *out_msg_len            = 0;

    // [1  enc_version]
    enc_version = *(p + off);
    if (enc_version != 1)
    {
        goto cleanup;
    }
    off += 1;

    // [1  suite]
    suite = *(p + off);
    if (suite != 1)
    {
        goto cleanup;
    }
    off += 1;
    // [2  reserved]
    off += 2;

    // [8  room_epoch]
    room_epoch = get_u64_be(p + off);
    off += 8;

    if (room_epoch != room->epoch)
    {
        fprintf(stderr, "room_epoch mismatch\n");
        goto cleanup;
    }

    // [8  seq]
    seq = get_u64_be(p + off);
    off += 8;

    // [16 nonce]
    memcpy(nonce, p + off, ENC_NONCE);
    off += ENC_NONCE;

    // [N  ciphertext]
    ciphertext = p + off;
    off += ciphertext_len;

    // [16 tag]
    tag = p + off;
    off += tag_len;

    if (off != msg_len)
    {
        fprintf(stderr, "msg_len mismatch\n");
        goto cleanup;
    }

    if (decrypt_chat_message(nonce, room->room_key, h->sender_id, h->room_id, room_epoch, seq,
                             ciphertext, ciphertext_len, tag, out_msg, out_msg_len) < 0)
    {
        fprintf(stderr, "decrypt_chat_message failed\n");
        goto cleanup;
    }

    if (check_recv_seq(room, h->sender_id, seq) < 0)
    {
        fprintf(stderr, "replay detected\n");
        goto cleanup;
    }

    ret = 0;
cleanup:
    if (ret != 0)
    {
        OPENSSL_free(*out_msg);
        *out_msg     = NULL;
        *out_msg_len = 0;
    }
    return ret;
}

int kuznechik_encrypt_message(uint8_t* nonce, uint8_t* enc_key, uint8_t* msg, int msg_len,
                              uint8_t* mac_key, uint8_t aad[AAD_FOR_ENC_CHAT_LEN], uint8_t** out,
                              uint16_t* out_len, uint8_t** tag_out, uint16_t* tag_out_len)
{
    if (!nonce || !enc_key || !msg || msg_len < 0 || msg_len > ENC_PLAINTEXT_MAX_LEN || !mac_key ||
        !tag_out || !out || !aad)
    {
        return -1;
    }

    int             ret         = -1;
    EVP_CIPHER*     cipher      = NULL;
    EVP_CIPHER_CTX* ctx         = NULL;
    uint8_t*        enc_msg     = NULL;
    int             enc_msg_len = 0;
    int             outl        = 0;
    EVP_MAC*        mac         = NULL;
    EVP_MAC_CTX*    mctx        = NULL;
    uint8_t*        tag         = NULL;

    cipher = EVP_CIPHER_fetch(NULL, "kuznyechik-ctr-acpkm", NULL);
    if (!cipher)
    {
        ossl_print_error("EVP_CIPHER_fetch");
        goto cleanup;
    }
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        ossl_print_error("EVP_CIPHER_CTX_new");
        goto cleanup;
    }
    if (EVP_EncryptInit_ex2(ctx, cipher, enc_key, nonce, NULL) != 1)
    {
        ossl_print_error("EVP_EncryptInit_ex2");
        goto cleanup;
    }
    enc_msg = OPENSSL_malloc(msg_len > 0 ? msg_len : 1);
    if (!enc_msg)
    {
        ossl_print_error("encrypted_room_key");
        goto cleanup;
    }
    if (EVP_EncryptUpdate(ctx, enc_msg, &outl, msg, msg_len) != 1)
    {
        ossl_print_error("EVP_EncryptUpdate");
        goto cleanup;
    }
    enc_msg_len += outl;
    if (EVP_EncryptFinal_ex(ctx, enc_msg + enc_msg_len, &outl) != 1)
    {
        ossl_print_error("EVP_EncryptFinal_ex");
        goto cleanup;
    }
    enc_msg_len += outl;

    mac = EVP_MAC_fetch(NULL, "kuznyechik-mac", NULL);
    if (!mac)
    {
        ossl_print_error("EVP_MAC_fetch");
        goto cleanup;
    }
    mctx = EVP_MAC_CTX_new(mac);
    if (!mctx)
    {
        ossl_print_error("EVP_MAC_CTX_new");
        goto cleanup;
    }
    if (EVP_MAC_init(mctx, mac_key, 32, NULL) != 1)
    {
        ossl_print_error("EVP_MAC_init");
        goto cleanup;
    }

    if (EVP_MAC_update(mctx, aad, AAD_FOR_ENC_CHAT_LEN) != 1)
    {
        ossl_print_error("EVP_MAC_update");
        goto cleanup;
    }
    if (EVP_MAC_update(mctx, nonce, ENC_NONCE) != 1)
    {
        ossl_print_error("EVP_MAC_update");
        goto cleanup;
    }
    if (EVP_MAC_update(mctx, enc_msg, enc_msg_len) != 1)
    {
        ossl_print_error("EVP_MAC_update");
        goto cleanup;
    }

    tag = OPENSSL_malloc(ENC_TAG);
    if (!tag)
    {
        ossl_print_error("OPENSSL_malloc");
        goto cleanup;
    }
    size_t mac_len  = 0;
    size_t mac_outl = 0;
    if (EVP_MAC_final(mctx, tag, &mac_outl, ENC_TAG) != 1)
    {
        ossl_print_error("EVP_MAC_final");
        goto cleanup;
    }
    mac_len += mac_outl;
    if (mac_len != ENC_TAG)
    {
        fprintf(stderr, "invalid mac_len: %zu\n", mac_len);
        goto cleanup;
    }

    if (enc_msg_len > UINT16_MAX)
    {
        fprintf(stderr, "enc_msg_len too large\n");
        goto cleanup;
    }
    *out = enc_msg;
    if (out_len)
    {
        *out_len = (uint16_t)enc_msg_len;
    }
    enc_msg  = NULL;
    *tag_out = tag;
    tag      = NULL;

    if (tag_out_len)
    {
        *tag_out_len = (uint16_t)mac_len;
    }

    ret = 0;
cleanup:
    OPENSSL_free(enc_msg);
    OPENSSL_free(tag);
    EVP_CIPHER_free(cipher);
    cipher = NULL;
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;
    EVP_MAC_CTX_free(mctx);
    mctx = NULL;
    EVP_MAC_free(mac);
    mac = NULL;

    return ret;
}

int kuznechik_decrypt_message(uint8_t* nonce, uint8_t* enc_key, uint8_t* msg, int msg_len,
                              uint8_t* mac_key, uint8_t aad[AAD_FOR_ENC_CHAT_LEN], uint8_t** out,
                              uint16_t* out_len, uint8_t* tag_in, uint16_t tag_in_len)
{
    if (!nonce || !enc_key || !msg || !mac_key || msg_len < 0 || msg_len > ENC_PLAINTEXT_MAX_LEN ||
        !out || !tag_in || !out_len)
    {
        return -1;
    }

    int             ret               = -1;
    EVP_CIPHER*     cipher            = NULL;
    EVP_CIPHER_CTX* ctx               = NULL;
    uint8_t*        decrypted_msg     = NULL;
    int             decrypted_msg_len = 0;
    int             outl              = 0;
    EVP_MAC*        mac               = NULL;
    EVP_MAC_CTX*    mctx              = NULL;
    uint8_t*        tag               = NULL;

    mac = EVP_MAC_fetch(NULL, "kuznyechik-mac", NULL);
    if (!mac)
    {
        ossl_print_error("EVP_MAC_fetch");
        goto cleanup;
    }
    mctx = EVP_MAC_CTX_new(mac);
    if (!mctx)
    {
        ossl_print_error("EVP_MAC_CTX_new");
        goto cleanup;
    }
    if (EVP_MAC_init(mctx, mac_key, 32, NULL) != 1)
    {
        ossl_print_error("EVP_MAC_init");
        goto cleanup;
    }

    if (EVP_MAC_update(mctx, aad, AAD_FOR_ENC_CHAT_LEN) != 1)
    {
        ossl_print_error("EVP_MAC_update");
        goto cleanup;
    }
    if (EVP_MAC_update(mctx, nonce, ENC_NONCE) != 1)
    {
        ossl_print_error("EVP_MAC_update");
        goto cleanup;
    }
    if (EVP_MAC_update(mctx, msg, msg_len) != 1)
    {
        ossl_print_error("EVP_MAC_update");
        goto cleanup;
    }

    tag = OPENSSL_malloc(ENC_TAG);
    if (!tag)
    {
        ossl_print_error("OPENSSL_malloc");
        goto cleanup;
    }
    size_t mac_len  = 0;
    size_t mac_outl = 0;
    if (EVP_MAC_final(mctx, tag, &mac_outl, ENC_TAG) != 1)
    {
        ossl_print_error("EVP_MAC_final");
        goto cleanup;
    }
    mac_len += mac_outl;
    if (mac_len != ENC_TAG || tag_in_len != ENC_TAG)
    {
        fprintf(stderr, "invalid mac_len: %zu\n", mac_len);
        goto cleanup;
    }
    if (CRYPTO_memcmp(tag, tag_in, tag_in_len) != 0)
    {
        fprintf(stderr, "invalid tag\n");
        goto cleanup;
    }

    cipher = EVP_CIPHER_fetch(NULL, "kuznyechik-ctr-acpkm", NULL);
    if (!cipher)
    {
        ossl_print_error("EVP_CIPHER_fetch");
        goto cleanup;
    }
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        ossl_print_error("EVP_CIPHER_CTX_new");
        goto cleanup;
    }
    if (EVP_DecryptInit_ex2(ctx, cipher, enc_key, nonce, NULL) != 1)
    {
        ossl_print_error("EVP_DecryptInit_ex2");
        goto cleanup;
    }
    decrypted_msg = OPENSSL_malloc(msg_len > 0 ? msg_len : 1);
    if (!decrypted_msg)
    {
        ossl_print_error("OPENSSL_malloc");
        goto cleanup;
    }
    if (EVP_DecryptUpdate(ctx, decrypted_msg, &outl, msg, msg_len) != 1)
    {
        ossl_print_error("EVP_DecryptUpdate");
        goto cleanup;
    }
    decrypted_msg_len += outl;
    if (EVP_DecryptFinal_ex(ctx, decrypted_msg + decrypted_msg_len, &outl) != 1)
    {
        ossl_print_error("EVP_DecryptFinal_ex");
        goto cleanup;
    }
    decrypted_msg_len += outl;
    if (decrypted_msg_len > ENC_PLAINTEXT_MAX_LEN)
    {
        fprintf(stderr, "decrypted_msg_len too large\n");
        goto cleanup;
    }
    *out = decrypted_msg;
    if (out_len)
    {
        *out_len = (uint16_t)decrypted_msg_len;
    }
    decrypted_msg = NULL;

    ret = 0;
cleanup:
    OPENSSL_clear_free(decrypted_msg, msg_len > 0 ? msg_len : 1);
    OPENSSL_free(tag);
    EVP_CIPHER_free(cipher);
    cipher = NULL;
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;
    EVP_MAC_CTX_free(mctx);
    mctx = NULL;
    EVP_MAC_free(mac);
    mac = NULL;

    return ret;
}

// PKT_AUTH_CHALLENGE
// [4 client_id]
// [32 random_nonce]
int server_send_challenge(int epfd, Client* c, uint32_t challenger_id, uint8_t* out_challenge,
                          uint32_t* message_id)
{
    uint8_t challenge[32];
    uint8_t payload[36];

    put_u32_be(payload, challenger_id);

    if (RAND_bytes(challenge, 32) != 1)
    {
        ossl_print_error("RAND_bytes failed");
        return -1;
    }
    memcpy(payload + 4, challenge, 32);

    Header h     = {0};
    h.flags      = 0;
    h.message_id = next_message_id(message_id);
    h.room_id    = 0;
    h.sender_id  = SERVER_ID;
    h.timestamp  = (uint64_t)time(NULL);
    h.type       = PKT_AUTH_CHALLENGE;
    h.version    = 1;

    if (enqueue_packet(c, &h, payload, 36) < 0)
    {
        fprintf(stderr, "enqueue_packet failed\n");
        return -1;
    }
    if (set_epollout_to_client(epfd, c) < 0)
    {
        fprintf(stderr, "set_epollout_to_client failed\n");
        return -1;
    }
    memcpy(out_challenge, challenge, 32);

    return 0;
}

// "chat_auth_v1" || client_id || username || challenge
static int get_sign_challenge(uint32_t client_id, const char* name, uint8_t* msg, uint16_t msg_len,
                              EVP_PKEY* private_key, unsigned char** out, size_t* out_len)
{
    if (!msg || !private_key || !out || !out_len || msg_len != (4 + CHALLENGE_LEN))
    {
        return -1;
    }
    int            ret    = -1;
    unsigned char* sigret = NULL;
    size_t         siglen = 0;
    EVP_MD*        md     = NULL;
    EVP_MD_CTX*    ctx    = NULL;
    uint8_t*       buf    = NULL;
    uint8_t*       p      = NULL;
    size_t         off    = 0;

    *out     = NULL;
    *out_len = 0;

    p                      = msg;
    uint32_t challenged_id = get_u32_be(p + off);
    if (challenged_id != client_id)
    {
        fprintf(stderr, "client id and challenge id are different\n");
        goto cleanup;
    }
    off += 4;

    uint8_t* challenge = p + off;

    md = EVP_MD_fetch(NULL, "md_gost12_512", NULL);
    if (!md)
    {
        ossl_print_error("EVP_MD_fetch");
        goto cleanup;
    }

    ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        ossl_print_error("EVP_MD_CTX_new");
        goto cleanup;
    }

    if (EVP_DigestSignInit(ctx, NULL, md, NULL, private_key) <= 0)
    {
        ossl_print_error("EVP_DigestSignInit failed");
        goto cleanup;
    }

    if (EVP_DigestSignUpdate(ctx, "chat_auth_v1", 12) <= 0)
    {
        ossl_print_error("EVP_DigestSignUpdate failed");
        goto cleanup;
    }

    uint8_t id_buf_be[4];
    put_u32_be(id_buf_be, client_id);

    if (EVP_DigestSignUpdate(ctx, id_buf_be, sizeof(id_buf_be)) <= 0)
    {
        ossl_print_error("EVP_DigestSignUpdate failed");
        goto cleanup;
    }

    if (EVP_DigestSignUpdate(ctx, name, strlen(name)) <= 0)
    {
        ossl_print_error("EVP_DigestSignUpdate failed");
        goto cleanup;
    }

    if (EVP_DigestSignUpdate(ctx, challenge, CHALLENGE_LEN) <= 0)
    {
        ossl_print_error("EVP_DigestSignUpdate failed");
        goto cleanup;
    }

    if (EVP_DigestSignFinal(ctx, NULL, &siglen) <= 0)
    {
        ossl_print_error("EVP_DigestSignFinal failed");
        goto cleanup;
    }
    sigret = OPENSSL_malloc(siglen);
    if (!sigret)
    {
        ossl_print_error("OPENSSL_malloc failed");
        goto cleanup;
    }

    if (EVP_DigestSignFinal(ctx, sigret, &siglen) <= 0)
    {
        ossl_print_error("EVP_DigestSignFinal failed");
        goto cleanup;
    }
    *out     = sigret;
    *out_len = siglen;
    sigret   = NULL;
    ret      = 0;
cleanup:
    OPENSSL_free(buf);
    OPENSSL_free(sigret);
    EVP_MD_free(md);
    EVP_MD_CTX_free(ctx);

    return ret;
}

int client_response_challenge(int epfd, Client* c, uint8_t* msg, uint16_t msg_len,
                              EVP_PKEY* private_key)
{
    if (!msg || !private_key)
    {
        return -1;
    }
    int      ret     = -1;
    uint8_t* out     = NULL;
    size_t   out_len = 0;
    if (get_sign_challenge(c->id, c->name, msg, msg_len, private_key, &out, &out_len) < 0)
    {
        fprintf(stderr, "get_sign_challenge failed\n");
        goto cleanup;
    }
    Header h     = {0};
    h.flags      = 0;
    h.message_id = 0;
    h.room_id    = 0;
    h.sender_id  = c->id;
    h.timestamp  = (uint64_t)time(NULL);
    h.type       = PKT_AUTH_RESPONSE;
    h.version    = 1;

    if (enqueue_packet(c, &h, out, out_len) < 0)
    {
        fprintf(stderr, "enqueue_packet failed\n");
        goto cleanup;
    }
    if (set_epollout_to_client(epfd, c) < 0)
    {
        fprintf(stderr, "set_epollout_to_client failed\n");
        goto cleanup;
    }
    ret = 0;
cleanup:
    OPENSSL_free(out);
    return ret;
}

// возвращает
// 1 правильная подпись
// 0 неправильная
// все остальное - ошибка
// "chat_auth_v1" || client_id || username || challenge
int server_verify_challenge(Client* c, uint8_t* msg, uint16_t msg_len)
{
    if (!c || !msg)
    {
        return -1;
    }

    if (!ksi_exists(c->name))
    {
        return -1;
    }
    EVP_PKEY* public_key = NULL;

    public_key = ksi_read_key(c->name);
    if (!public_key)
    {
        fprintf(stderr, "ksi_read_key failed\n");
        return -1;
    }

    int         ret  = -1;
    EVP_MD*     md   = NULL;
    EVP_MD_CTX* ctx  = NULL;
    uint8_t*    data = NULL;

    md = EVP_MD_fetch(NULL, "md_gost12_512", NULL);
    if (!md)
    {
        ossl_print_error("EVP_MD_fetch");
        goto cleanup;
    }
    ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        ossl_print_error("EVP_MD_CTX_new\n");
        goto cleanup;
    }

    if (EVP_DigestVerifyInit(ctx, NULL, md, NULL, public_key) <= 0)
    {
        fprintf(stderr, "EVP_DigestVerifyInit failed\n");
        goto cleanup;
    }

    if (EVP_DigestVerifyUpdate(ctx, "chat_auth_v1", 12) <= 0)
    {
        ossl_print_error("EVP_DigestVerifyUpdate failed");
        goto cleanup;
    }

    uint8_t id_buf_be[4];
    put_u32_be(id_buf_be, c->id);
    if (EVP_DigestVerifyUpdate(ctx, id_buf_be, sizeof(id_buf_be)) <= 0)
    {
        ossl_print_error("EVP_DigestVerifyUpdate failed");
        goto cleanup;
    }

    if (EVP_DigestVerifyUpdate(ctx, c->name, strlen(c->name)) <= 0)
    {
        ossl_print_error("EVP_DigestVerifyUpdate failed");
        goto cleanup;
    }

    if (EVP_DigestVerifyUpdate(ctx, c->challenge, CHALLENGE_LEN) <= 0)
    {
        ossl_print_error("EVP_DigestVerifyUpdate failed");
        goto cleanup;
    }

    int rc = EVP_DigestVerifyFinal(ctx, msg, msg_len);
    if (rc == 1)
    {
        ret = 1;
    }
    else if (rc == 0)
    {
        ret = 0;
    }
    else
    {
        ossl_print_error("EVP_DigestVerifyFinal failed\n");
        goto cleanup;
    }

cleanup:
    EVP_PKEY_free(public_key);
    EVP_MD_free(md);
    EVP_MD_CTX_free(ctx);
    OPENSSL_free(data);
    return ret;
}

// 1 matches
// 0 not
int key_bundle_matches_ksi(Client* c, const uint8_t* data, uint16_t data_len)
{
    if (!c || !data || data_len == 0)
        return -1;

    int ret = 0;

    KeyBundle* kb                 = NULL;
    EVP_PKEY*  registered_pub     = NULL;
    uint8_t*   registered_der     = NULL;
    uint16_t   registered_der_len = 0;

    kb = deserialize_key_bundle_full(data, data_len);
    if (!kb)
        goto cleanup;

    if (kb->client_id != c->id)
    {
        fprintf(stderr, "bundle client_id mismatch\n");
        goto cleanup;
    }

    registered_pub = ksi_read_key(c->name);
    if (!registered_pub)
        goto cleanup;

    if (key_to_der_pub(registered_pub, &registered_der, &registered_der_len) < 0)
        goto cleanup;

    if (kb->identity_pub_len != registered_der_len)
    {
        fprintf(stderr, "identity key len mismatch\n");
        goto cleanup;
    }

    if (CRYPTO_memcmp(kb->identity_pub, registered_der, registered_der_len) != 0)
    {
        fprintf(stderr, "identity key mismatch\n");
        goto cleanup;
    }

    ret = 1;

cleanup:
    kb_free(kb);
    EVP_PKEY_free(registered_pub);
    OPENSSL_free(registered_der);
    return ret;
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

// "chat_auth_v1" || client_id || name || nonce || identity_pub_der
int get_sign_register_commit(uint32_t client_id, const char* name, const uint8_t* nonce,
                             EVP_PKEY* private_key, const uint8_t* identity_pub_der,
                             uint16_t identity_pub_der_len, unsigned char** out, size_t* out_len)
{
    if (!private_key || !out || !out_len)
    {
        return -1;
    }
    int            ret    = -1;
    unsigned char* sigret = NULL;
    size_t         siglen = 0;
    EVP_MD*        md     = NULL;
    EVP_MD_CTX*    ctx    = NULL;
    uint8_t*       buf    = NULL;

    *out     = NULL;
    *out_len = 0;

    md = EVP_MD_fetch(NULL, "md_gost12_512", NULL);
    if (!md)
    {
        ossl_print_error("EVP_MD_fetch");
        goto cleanup;
    }

    ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        ossl_print_error("EVP_MD_CTX_new");
        goto cleanup;
    }

    if (EVP_DigestSignInit(ctx, NULL, md, NULL, private_key) <= 0)
    {
        ossl_print_error("EVP_DigestSignInit failed");
        goto cleanup;
    }

    if (EVP_DigestSignUpdate(ctx, "chat_register_v1", 16) <= 0)
    {
        ossl_print_error("EVP_DigestSignUpdate failed");
        goto cleanup;
    }

    uint8_t id_buf_be[4];
    put_u32_be(id_buf_be, client_id);

    if (EVP_DigestSignUpdate(ctx, id_buf_be, sizeof(id_buf_be)) <= 0)
    {
        ossl_print_error("EVP_DigestSignUpdate failed");
        goto cleanup;
    }

    if (EVP_DigestSignUpdate(ctx, name, strlen(name)) <= 0)
    {
        ossl_print_error("EVP_DigestSignUpdate failed");
        goto cleanup;
    }

    if (EVP_DigestSignUpdate(ctx, nonce, CHALLENGE_LEN) <= 0)
    {
        ossl_print_error("EVP_DigestSignUpdate failed");
        goto cleanup;
    }
    if (EVP_DigestSignUpdate(ctx, identity_pub_der, identity_pub_der_len) <= 0)
    {
        ossl_print_error("EVP_DigestSignUpdate failed");
        goto cleanup;
    }

    if (EVP_DigestSignFinal(ctx, NULL, &siglen) <= 0)
    {
        ossl_print_error("EVP_DigestSignFinal failed");
        goto cleanup;
    }
    sigret = OPENSSL_malloc(siglen);
    if (!sigret)
    {
        ossl_print_error("OPENSSL_malloc failed");
        goto cleanup;
    }

    if (EVP_DigestSignFinal(ctx, sigret, &siglen) <= 0)
    {
        ossl_print_error("EVP_DigestSignFinal failed");
        goto cleanup;
    }
    *out     = sigret;
    *out_len = siglen;
    sigret   = NULL;
    ret      = 0;
cleanup:
    OPENSSL_free(buf);
    OPENSSL_free(sigret);
    EVP_MD_free(md);
    EVP_MD_CTX_free(ctx);

    return ret;
}

// [2 identity_pub_der_len]
// [identity_pub_der]
// [2 signature_len]
// [signature]
// "chat_auth_v1" || client_id || name || nonce || identity_pub_der
int verify_register_commit(uint32_t client_id, const char* name, uint8_t* nonce, uint8_t* msg,
                           uint16_t msg_len, EVP_PKEY** out_identity_pub)
{
    if (!name || !nonce || !msg || !out_identity_pub)
    {
        return -1;
    }
    int         ret                  = -1;
    EVP_MD*     md                   = NULL;
    EVP_MD_CTX* ctx                  = NULL;
    uint8_t*    buf                  = NULL;
    uint8_t*    p                    = NULL;
    size_t      off                  = 0;
    uint8_t*    identity_pub_der     = NULL;
    uint16_t    identity_pub_der_len = 0;
    uint8_t*    sig                  = NULL;
    uint16_t    siglen               = 0;
    EVP_PKEY*   public_key           = NULL;

    p = msg;
#define NEED_2(x)                                                                                  \
    do                                                                                             \
    {                                                                                              \
        if ((off > (size_t)msg_len) || ((size_t)(msg_len - off) < (size_t)(x)))                    \
        {                                                                                          \
            goto cleanup;                                                                          \
        }                                                                                          \
    } while (0)

    NEED_2(2);
    identity_pub_der_len = get_u16_be(p + off);
    off += 2;

    NEED_2(identity_pub_der_len);
    identity_pub_der = p + off;
    off += identity_pub_der_len;

    NEED_2(2);
    siglen = get_u16_be(p + off);
    off += 2;

    NEED_2(siglen);
    sig = p + off;
    off += siglen;

    if (off != msg_len)
    {
        fprintf(stderr, "msg_len wrong\n");
        return -1;
    }

    md = EVP_MD_fetch(NULL, "md_gost12_512", NULL);
    if (!md)
    {
        ossl_print_error("EVP_MD_fetch");
        goto cleanup;
    }

    ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        ossl_print_error("EVP_MD_CTX_new");
        goto cleanup;
    }

    if (der_to_key_pub(&public_key, identity_pub_der, identity_pub_der_len) < 0 || !public_key)
    {
        fprintf(stderr, "der_to_key_pub failed\n");
        goto cleanup;
    }

    if (EVP_DigestVerifyInit(ctx, NULL, md, NULL, public_key) <= 0)
    {
        ossl_print_error("EVP_DigestVerifyInit failed");
        goto cleanup;
    }

    if (EVP_DigestVerifyUpdate(ctx, "chat_register_v1", 16) <= 0)
    {
        ossl_print_error("EVP_DigestVerifyUpdate failed");
        goto cleanup;
    }

    uint8_t id_buf_be[4];
    put_u32_be(id_buf_be, client_id);

    if (EVP_DigestVerifyUpdate(ctx, id_buf_be, sizeof(id_buf_be)) <= 0)
    {
        ossl_print_error("EVP_DigestVerifyUpdate failed");
        goto cleanup;
    }

    if (EVP_DigestVerifyUpdate(ctx, name, strlen(name)) <= 0)
    {
        ossl_print_error("EVP_DigestVerifyUpdate failed");
        goto cleanup;
    }

    if (EVP_DigestVerifyUpdate(ctx, nonce, CHALLENGE_LEN) <= 0)
    {
        ossl_print_error("EVP_DigestVerifyUpdate failed");
        goto cleanup;
    }
    if (EVP_DigestVerifyUpdate(ctx, identity_pub_der, identity_pub_der_len) <= 0)
    {
        ossl_print_error("EVP_DigestVerifyUpdate failed");
        goto cleanup;
    }

    int sigret = EVP_DigestVerifyFinal(ctx, sig, siglen);
    if (sigret == 0)
    {
        ret = 0;
        goto cleanup;
    }

    else if (sigret == 1)
    {
        ret = 1;
    }
    else
    {
        ret = -1;
        ossl_print_error("EVP_DigestVerifyFinal");
        goto cleanup;
    }
    *out_identity_pub = public_key;
    public_key        = NULL;
cleanup:
    OPENSSL_free(buf);
    EVP_PKEY_free(public_key);
    EVP_MD_free(md);
    EVP_MD_CTX_free(ctx);

    return ret;
}

int get_challenge(uint8_t challenge[CHALLENGE_LEN])
{
    if (RAND_bytes(challenge, CHALLENGE_LEN) != 1)
    {
        ossl_print_error("RAND_bytes");
        return -1;
    }
    return 0;
}