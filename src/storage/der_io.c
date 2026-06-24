#include "storage/der_io.h"

#include "crypto/crypto_core.h"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

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
