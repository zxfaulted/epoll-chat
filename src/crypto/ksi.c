#include "crypto/ksi.h"

#include "crypto/crypto.h"
#include "storage/fs_utils.h"
#include "storage/pem_io.h"

#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

int ensure_ksi_dir(const char* name)
{
    if (!is_name_safe(name))
    {
        fprintf(stderr, "name is not safe\n");
        return -1;
    }
    if (mkdir("./ksi", 0700) < 0 && errno != EEXIST)
    {
        perror("mkdir");
        return -1;
    }
    char path_with_name[256];
    snprintf(path_with_name, sizeof(path_with_name), "./ksi/%s/", name);
    if (mkdir(path_with_name, 0700) < 0 && errno != EEXIST)
    {
        perror("mkdir");
        return -1;
    }
    return 0;
}

int ksi_write_key(const char* name, EVP_PKEY* key)
{
    if (!is_name_safe(name))
    {
        fprintf(stderr, "name is not safe\n");
        return -1;
    }
    if (ensure_ksi_dir(name) < 0)
    {
        fprintf(stderr, "ensure_ksi_dir failed\n");
        return -1;
    }
    char path_with_name[256];
    snprintf(path_with_name, sizeof(path_with_name), "./ksi/%s/identity_public.pem", name);
    if (pem_write_public_key(path_with_name, key) < 0)
    {
        return -1;
    }
    return 0;
}

EVP_PKEY* ksi_read_key(const char* name)
{
    if (!is_name_safe(name))
    {
        fprintf(stderr, "name is not safe\n");
        return NULL;
    }
    char path_with_name[256];
    snprintf(path_with_name, sizeof(path_with_name), "./ksi/%s/identity_public.pem", name);
    if (!file_exists(path_with_name))
    {
        fprintf(stderr, "file does not exist\n");
        return NULL;
    }
    EVP_PKEY* key = NULL;
    if (pem_read_public_key(path_with_name, &key) < 0)
    {
        return NULL;
    }
    return key;
}

int ksi_make_entry(const char* name, EVP_PKEY* key)
{
    if (!is_name_safe(name))
    {
        fprintf(stderr, "name is not safe\n");
        return -1;
    }
    if (ensure_ksi_dir(name) < 0)
    {
        fprintf(stderr, "ensure_ksi_dir failed\n");
        return -1;
    }
    if (ksi_write_key(name, key) < 0)
    {
        fprintf(stderr, "ksi_write_key failed\n");
        return -1;
    }
    return 0;
}

int is_name_safe(const char* name)
{
    if (!name)
    {
        return -1;
    }
    size_t name_len = 0;
    name_len        = strlen(name);
    if (name_len == 0 || name_len > MAX_NAME_LEN)
    {
        return 0;
    }
    for (size_t i = 0; i < name_len; i++)
    {
        unsigned char c = (unsigned char)name[i];
        if (!((isalnum(c) || c == '-' || c == '_')))
        {
            return 0;
        }
    }
    return 1;
}

int ksi_exists(const char* name)
{
    if (is_name_safe(name) != 1)
    {
        fprintf(stderr, "name is not safe\n");
        return 0;
    }
    char path_with_name[256];
    snprintf(path_with_name, sizeof(path_with_name), "./ksi/%s/identity_public.pem", name);
    return file_exists(path_with_name);
}
