#ifndef KSI_H
#define KSI_H

#include <openssl/evp.h>

int       ensure_ksi_dir(const char* name);
int       ksi_write_key(const char* name, EVP_PKEY* key);
EVP_PKEY* ksi_read_key(const char* name);
int       ksi_make_entry(const char* name, EVP_PKEY* key);
int       is_name_safe(const char* name);
int       ksi_exists(const char* name);

#endif /* KSI_H */