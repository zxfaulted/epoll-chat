#ifndef EPOLL_IO_H
#define EPOLL_IO_H

#include "transport/connection.h"

int set_epollout_to_client(int epfd, Client* c);
int unset_epollout_to_client(int epfd, Client* c);

#endif