#ifndef DER_IO_H
#define DER_IO_H

#include <openssl/evp.h>

int der_write_private_key(const char* path, EVP_PKEY* key);
int der_read_public_key(const char* path, EVP_PKEY** key);
int key_to_der_pub(EVP_PKEY* key, uint8_t** out, uint16_t* out_len);
int der_to_key_pub(EVP_PKEY** out, uint8_t* in, uint16_t in_len);

#endif