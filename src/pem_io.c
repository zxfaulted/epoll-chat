#include "pem_io.h"
#include <openssl/pem.h>

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