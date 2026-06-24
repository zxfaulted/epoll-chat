#ifndef PEM_IO_H
#define PEM_IO_H

#include "crypto/crypto.h"
#include <openssl/evp.h>

int pem_write_private_key(const char* path, EVP_PKEY* key);
int pem_write_public_key(const char* path, EVP_PKEY* key);

int pem_read_private_key(const char* path, EVP_PKEY** key);
int pem_read_public_key(const char* path, EVP_PKEY** key);

#endif // PEM_IO_H