#include "storage/fs_utils.h"

#include <stdio.h>
#include <sys/errno.h>
#include <sys/stat.h>

int ensure_dir(const char* dir, const char* name)
{
    if (mkdir(dir, 0700) < 0 && errno != EEXIST)
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

int file_exists(const char* path)
{
    struct stat st;

    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}