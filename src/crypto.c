#include "crypto.h"
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/provider.h>

int fill_in_key_bundle(KeyBundle* kb, uint32_t client_id, IdentityKeyAlg ika, uint8_t* ika_pub,
                       uint16_t ika_len, FingerprintAlg fingerprint_alg, uint8_t* fingerprint,
                       uint8_t fingerprint_len, SignatureAlg signature_alg, uint8_t* signature,
                       uint16_t signature_len, VKOAlg vko_alg, uint8_t* vko_pub,
                       uint16_t vko_pub_len)
{
    kb->bundle_version = 1;
    kb->client_id      = client_id;
    kb->vko_expires_at = (uint32_t)time(NULL) + 24ULL * 60 * 60;

    kb->identity_key_alg = ika;
    kb->identity_pub     = ika_pub;
    kb->identity_pub_len = ika_len;

    kb->fingerprint_alg = fingerprint_alg;
    kb->fingerprint     = fingerprint;
    kb->fingerprint_len = fingerprint_len;

    kb->signature_alg = signature_alg;
    kb->signature     = signature;
    kb->signature_len = signature_len;

    kb->vko_alg = vko_alg;
    kb->vko_pub;
    kb->vko_pub_len = vko_pub_len;
    return 0;
}

void openssl_print_error(const char* where)
{
    fprintf(stderr, "[OPENSSL ERROR] %s\n", where);
    ERR_print_errors_fp(stderr);
}

int openssl_init_crypto()
{
    OSSL_PROVIDER* dflt = OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER* gost = OSSL_PROVIDER_load(NULL, "gost");
    if (!dflt || !gost)
    {
        return -1;
    }
    return 0;
}

int kb_free(KeyBundle* kb)
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

static int pem_write_private_key(const char* path, EVP_PKEY* key)
{
    FILE* f = fopen(path, "wb");
    if (!f)
    {
        perror("fopen");
        return -1;
    }
    if (!PEM_write_PrivateKey(f, key, NULL, NULL, 0, NULL, NULL))
    {
        openssl_print_error("pem write private key");
        return -1;
    }
    fclose(f);
    return 0;
}

static EVP_PKEY* pem_read_private_key(const char* path)
{
    FILE* f = fopen(path, "rb");
    if (!f)
    {
        return NULL;
    }
    EVP_PKEY* e = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    if (e == NULL)
    {
        openssl_print_error("pem write private key");
        return NULL;
    }
    fclose(f);
    return e;
}

static int pem_write_public_key(const char* path, EVP_PKEY* key)
{
    FILE* f = fopen(path, "wb");
    if (!f)
    {
        perror("fopen");
        return -1;
    }
    if (!PEM_write_PUBKEY(f, key))
    {
        openssl_print_error("pem write private key");
        return -1;
    }
    fclose(f);
    return 0;
}

static EVP_PKEY* pem_read_public_key(const char* path)
{
    FILE* f = fopen(path, "rb");
    if (!f)
    {
        return NULL;
    }
    EVP_PKEY* e = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    if (e == NULL)
    {
        openssl_print_error("pem write public key");
        fclose(f);
        return NULL;
    }
    fclose(f);
    return e;
}

EVP_PKEY* generate_key(const char* name)
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);
    if (ctx == NULL)
    {
        openssl_print_error("EVP_PKEY_CTX_new_from_name");
        return NULL;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        openssl_print_error("EVP_PKEY_keygen_init");
        return NULL;
    }
    EVP_PKEY* key;
    if (EVP_PKEY_generate(ctx, &key) <= 0)
    {
        openssl_print_error("EVP_PKEY_generate");
        return NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return key;
}

int key_to_der_pub(EVP_PKEY* key, uint8_t** out, uint16_t* out_len)
{
    uint8_t* der   = NULL;
    int      bytes = i2d_PUBKEY(key, der);
    if (bytes < 0)
    {
        openssl_print_error("i2d_PUBKEY");
        return -1;
    }
    if (bytes > 65535)
    {
        openssl_print_error("i2d_PUBKEY");
        return -1;
    }
    if (der != NULL)
    {
        *out_len = bytes;
        *out     = der;
        return 0;
    }
    return -1;
}

int der_to_key_pub(EVP_PKEY* out, uint8_t** in, uint16_t* in_len)
{
    EVP_PKEY* key   = NULL;
    int       bytes = d2i_PUBKEY(&key, in, *in_len);
    if (bytes < 0)
    {
        openssl_print_error("i2d_PUBKEY");
        return -1;
    }
    if (bytes > 65535)
    {
        openssl_print_error("i2d_PUBKEY");
        return -1;
    }
    if (key != NULL)
    {
        out = key;
        return 0;
    }
    return -1;
}

int get_hash(uint8_t* identity_pub, uint16_t identity_len, uint8_t* out, uint16_t* out_len)
{
    EVP_MD*     md  = NULL;
    EVP_MD_CTX* ctx = NULL;

    md = EVP_MD_fetch(NULL, "md_gost12_512", "provider=gost");

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        openssl_print_error("EVP_MD_CTX_new()");
        EVP_MD_free(md);
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    if (EVP_DigestInit_ex(ctx, md, NULL) <= 0)
    {
        openssl_print_error("EVP_DigestInit_ex");
        EVP_MD_free(md);
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    if (EVP_DigestUpdate(ctx, identity_pub, identity_len) <= 0)
    {
        openssl_print_error("EVP_DigestInit_ex");
        EVP_MD_free(md);
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    if (EVP_DigestFinal_ex(ctx, out, &out_len) <= 0)
    {
        openssl_print_error("EVP_DigestFinal_ex");
        EVP_MD_free(md);
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    EVP_MD_free(md);
    EVP_MD_CTX_free(ctx);
    return 0;
}

int init_key_bundle(KeyBundle* kb, uint32_t client_id)
{
    IdentityKeyAlg ika     = IKA_GOST2012_512;
    EVP_PKEY*      ika_evp = pem_read_public_key("../keys/identity.pub");
    if (ika_evp == NULL)
    {
        fprintf(stderr, "[ERROR] pem_read_public_key FAULTED");
        return -1;
    }

    uint16_t ika_len = 0;
    uint8_t* ika_pub = NULL;
    if (key_to_der_pub(&ika_evp, &ika_pub, &ika_len) < 0)
    {
        fprintf(stderr, "[ERROR] key_to_der_pub  FAULTED");
        return -1;
    }

    VKOAlg    vko_a   = VKO_GOST2012_512;
    EVP_PKEY* vko_evp = pem_read_public_key("../keys/vko.pub");
    if (vko_evp == NULL)
    {
        fprintf(stderr, "[ERROR] pem_read_public_key FAULTED");
        return -1;
    }

    uint16_t vko_len = 0;
    uint8_t* vko_pub = NULL;
    if (key_to_der_pub(&vko_evp, &vko_pub, &vko_len) < 0)
    {

        fprintf(stderr, "[ERROR] key_to_der_pub  FAULTED");
        return -1;
    }

    FingerprintAlg fingerprint_alg = FA_GOST2012_512;
    uint8_t*       fingerprint;
    uint16_t       fingerprint_len;
    if (get_hash(ika_pub, ika_len, fingerprint, &fingerprint_len) < 0)
    {
        fprintf(stderr, "[ERROR] get_fingerprint FAULTED");
        return -1;
    }

    SignatureAlg signature_alg = SigA_512;

    fill_in_key_bundle(kb, client_id, ika_pub, ika_len);
}

uint8_t* create_bundle_to_sign()
{
    uint8_t  bundle_version;
    uint32_t client_id;

    // gost2012_256
    // gost2012_512
    uint8_t  identity_key_alg;
    uint16_t identity_pub_len;
    uint8_t* identity_pub;

    // выработка ключа общего (секрета)
    // gost2012_256
    // gost2012_512
    uint8_t  vko_alg;
    uint16_t vko_pub_len;
    uint8_t* vko_pub;
    uint64_t vko_expires_at;

    // md_gost12_512
    uint8_t  fingerprint_alg;
    uint16_t fingerprint_len;
    uint8_t* fingerprint;

    // 1 = gost3410_2012_256_with_gost3411_2012_256
    // 2 = gost3410_2012_512_with_gost3411_2012_512
    // gost2012_256
    uint8_t  signature_alg;
    uint16_t signature_len;
    uint8_t* signature;
}