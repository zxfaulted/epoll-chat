#include "transport/epoll_io.h"

#include <stdio.h>
#include <sys/epoll.h>

// 0 успех
// -1 ошибка
int set_epollout_to_client(int epfd, Client* c)
{
    struct epoll_event ev;
    ev.data.ptr = c;
    ev.events   = EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLRDHUP | EPOLLERR;
    if (epoll_ctl(epfd, EPOLL_CTL_MOD, c->ei.fd, &ev) < 0)
    {
        perror("epoll_ctl mod epollout");
        return -1;
    }
    return 0;
}

int unset_epollout_to_client(int epfd, Client* c)
{
    struct epoll_event ev;
    ev.data.ptr = c;
    ev.events   = EPOLLIN | EPOLLHUP | EPOLLRDHUP | EPOLLERR;
    if (epoll_ctl(epfd, EPOLL_CTL_MOD, c->ei.fd, &ev) < 0)
    {
        perror("epoll_ctl mod epollout");
        return -1;
    }
    return 0;
}