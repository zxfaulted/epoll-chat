#include "net.h"
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define SERVER_PORT 5555
#define SERVER_ADDRESS "127.0.0.1"

int main()
{
    signal(SIGPIPE, SIG_IGN);

    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0)
    {
        perror("socket");
        return -1;
    }

    struct sockaddr_in server_sa;
    socklen_t          server_len = sizeof(server_sa);
    memset(&server_sa, 0, server_len);
    inet_pton(AF_INET, SERVER_ADDRESS, &server_sa.sin_addr);
    server_sa.sin_family = AF_INET;
    server_sa.sin_port   = htons(SERVER_PORT);

    if (connect(client_fd, (struct sockaddr*)&server_sa, server_len) < 0)
    {
        perror("connect");
        close(client_fd);
        return -1;
    }

    if (set_nonblocking(client_fd) < 0)
    {
        close(client_fd);
        return -1;
    }
    int epfd = epoll_create1(EPOLL_CLOEXEC);

    Client* c = malloc(sizeof(Client));
    memset(c, 0, sizeof(Client));
    c->ei.fd   = client_fd;
    c->ei.item = CLIENT_ITEM;
    c->state   = STATE_WAIT_NAME;

    struct epoll_event ev;
    ev.data.ptr = c;
    ev.events   = EPOLLIN | EPOLLHUP | EPOLLRDHUP | EPOLLERR;

    epoll_ctl(epfd, EPOLL_CTL_ADD, c->ei.fd, &ev);

    EpollItem* stdin = malloc(sizeof(EpollItem));
    stdin->fd        = STDIN_FILENO;
    stdin->item      = STDIN_ITEM;
    ev.data.ptr      = stdin;
    ev.events        = EPOLLIN;
    epoll_ctl(epfd, EPOLL_CTL_ADD, STDIN_FILENO, &ev);

    struct epoll_event events[2];
    memset(events, 0, sizeof(events));

    uint32_t message_count = 0;
    while (1)
    {
        int nfds = epoll_wait(epfd, events, 2, -1);
        for (int i = 0; i < nfds; i++)
        {
            uint32_t   cur_evs = events[i].events;
            EpollItem* ei      = (EpollItem*)events[i].data.ptr;

            if (ei->item == STDIN_ITEM && cur_evs & EPOLLIN)
            {
                char out_buf[512];
                memset(&out_buf, 0, sizeof(out_buf));
                int bytes = read(ei->fd, out_buf, sizeof(out_buf));
                if (bytes > 0)
                {
                    if (out_buf[bytes - 1] == '\n')
                    {
                        bytes--;
                    }
                    if (bytes > 0)
                    {
                        Header h;
                        memset(&h, 0, sizeof(h));

                        h.version    = 1;
                        h.flags      = 0;
                        h.room_id    = 0;
                        h.timestamp  = (uint64_t)time(NULL);
                        h.message_id = message_count++;

                        if (c->state == STATE_WAIT_NAME)
                        {
                            h.type      = PKT_NAME;
                            h.sender_id = 0;
                        }
                        if (c->state == STATE_READY)
                        {
                            h.type      = PKT_CHAT;
                            h.sender_id = c->id;
                        }

                        if (enqueue_packet(c, &h, out_buf, bytes) < 0)
                        {
                            continue;
                        }
                        if (set_epollout_to_client(epfd, c) < 0)
                        {
                            perror("epoll_ctl MOD");
                            close(client_fd);
                            close(epfd);
                            free(c);
                            return -1;
                        }
                    }
                }
            }

            if ((ei->item == CLIENT_ITEM) && (cur_evs & EPOLLIN))
            {
                Client*  c = (Client*)ei;
                char     msg[MESSAGE_SIZE];
                uint32_t msg_len;

                while (1)
                {
                    int rc = recv_into_inbuf(c);
                    if (rc < 0)
                    {
                        close(c->ei.fd);
                        close(epfd);
                        free(c);
                        return 0;
                    }
                    if (rc == 0)
                    {
                        break;
                    }
                }
                while (1)
                {
                    Header h;
                    memset(&h, 0, sizeof(h));
                    int rc = try_pop_packet(c, &h, msg, &msg_len);
                    if (rc < 0)
                    {
                        close(c->ei.fd);
                        close(epfd);
                        free(c);
                        return 0;
                    }
                    else if (rc == 0)
                    {
                        break;
                    }
                    else
                    {
                        if (h.type == PKT_JOIN)
                        {
                            c->state = STATE_READY;
                            parse_client_id_and_name(msg, msg_len, &c->id, c->name);
                            printf("[JOIN] %s#%" PRIu32 "\n", c->name, c->id);
                        }
                        printf("%s#%" PRIu32 ": %s\n", c->name, h.sender_id, msg);
                    }
                }
            }
            if ((ei->item == CLIENT_ITEM) && cur_evs & EPOLLOUT)
            {
                Client* c  = (Client*)ei;
                int     rc = flush_send(c);
                if (rc < 0)
                {
                    close(client_fd);
                    close(epfd);
                    perror("flush_send");
                    free(c);
                    return -1;
                }
                else if (c->conn.out_len == 0)
                {
                    struct epoll_event ev;
                    ev.data.ptr = c;
                    ev.events   = EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR;
                    epoll_ctl(epfd, EPOLL_CTL_MOD, client_fd, &ev);
                }
                else if (rc == 0)
                {
                    continue;
                }
            }
            if (cur_evs & EPOLLHUP || cur_evs & EPOLLRDHUP)
            {
                if (ei->item == CLIENT_ITEM)
                {
                    Client* c = (Client*)ei;
                    close(c->ei.fd);
                    free(c);
                }
                else if (ei->item == STDIN_ITEM)
                {
                    close(ei->fd);
                    free(ei);
                }
                close(epfd);
                return 0;
            }
        }
    }
    close(client_fd);
    close(epfd);
    free(c);
    return 0;
}