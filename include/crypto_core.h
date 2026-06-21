#ifndef CRYPTO_CORE_H
#define CRYPTO_CORE_H
#include <openssl/provider.h>

int       ossl_init_crypto(OSSL_PROVIDER** dflt, OSSL_PROVIDER** gost);
int       ossl_destroy_crypto(OSSL_PROVIDER** dflt, OSSL_PROVIDER** gost);
void      ossl_print_error(const char* where);
EVP_PKEY* generate_identity_key(void);
EVP_PKEY* generate_vko_key(void);
EVP_PKEY* generate_key(const char* name);
int derive_raw_secret(EVP_PKEY* my_vko_private, EVP_PKEY* peer, uint8_t** out, size_t* out_len);
int get_kdf(uint8_t* secret_key, uint16_t secret_key_len, const uint8_t* salt, uint16_t salt_len,
            uint8_t* info, uint16_t info_len, uint8_t* out_key, size_t out_key_len);
#endif