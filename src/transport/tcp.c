#include "transport/tcp.h"

#include <fcntl.h>

// 0 успех
// -1 ошибка
int set_nonblocking(int server_fd)
{
    int flags = fcntl(server_fd, F_GETFL, 0);
    if (flags < 0)
    {
        return -1;
    }
    if (fcntl(server_fd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        return -1;
    }
    return 0;
}