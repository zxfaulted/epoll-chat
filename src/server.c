#include "net.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
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

int main()
{
    signal(SIGPIPE, SIG_IGN);
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
    {
        perror("socket");
        return -1;
    }

    struct sockaddr_in server_sa;
    socklen_t          server_len = sizeof(server_sa);
    memset(&server_sa, 0, server_len);
    server_sa.sin_addr.s_addr = INADDR_ANY;
    server_sa.sin_family      = AF_INET;
    server_sa.sin_port        = htons(SERVER_PORT);

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1)
    {
        perror("setsockopt");
        close(server_fd);
        return 1;
    }

    if (bind(server_fd, (struct sockaddr*)&server_sa, server_len) < 0)
    {
        perror("bind");
        return -1;
    }

    if (listen(server_fd, SOMAXCONN) < 0)
    {
        perror("listen");
        return -1;
    }

    if (set_nonblocking(server_fd) < 0)
    {
        close(server_fd);
        return -1;
    }
    Server* server = malloc(sizeof(Server));
    server->sa     = server_sa;

    server->ei.fd   = server_fd;
    server->ei.item = SERVER_ITEM;

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events   = EPOLLIN;
    ev.data.ptr = server;

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, server->ei.fd, &ev) < 0)
    {
        perror("epoll ADD server");
        close(server_fd);
        free(server);
        return -1;
    };

    struct epoll_event events[MAX_EVENTS];

    int     clients_count = 0;
    Client* clients[MAX_CLIENTS];
    memset(clients, 0, sizeof(clients));
    uint32_t client_id  = 1;
    uint32_t message_id = 0;
    int      client_removed;
    while (1)
    {
        int nfds = epoll_wait(epfd, events, MAX_EVENTS, -1);
        for (int i = 0; i < nfds; i++)
        {
            client_removed   = 0;
            uint32_t cur_evs = events[i].events;

            EpollItem* ei = events[i].data.ptr;

            // появился новый клиент
            if (ei->item == SERVER_ITEM)
            {
                // Server* s = (Server*)ei;
                add_new_client(epfd, server_fd, clients, &clients_count, &client_id);
            }
            else if (ei->item == CLIENT_ITEM)
            {
                Client* c = (Client*)ei;
                if (cur_evs & EPOLLIN)
                {
                    switch (c->state)
                    {
                        char     msg[MESSAGE_SIZE];
                        uint32_t msg_len;
                        int      rc;
                        case STATE_WAIT_NAME:
                            rc = recv_into_inbuf(c);
                            if (rc == 0)
                            {
                                break;
                            }
                            if (rc < 0)
                            {
                                perror("recv_into_buf PKT_NAME");
                                disconnect_client(epfd, c, clients, &clients_count, message_id++);
                                continue;
                            }
                            Header h = {0};
                            rc       = try_pop_packet(c, &h, msg, &msg_len);
                            if (rc < 0)
                            {
                                reject_packet(epfd, c, c->ei.fd, clients, &clients_count,
                                              "POP_PACKET_ERROR", message_id++);
                                client_removed = 1;
                                continue;
                            }
                            PacketState p_st = validate_packet_name(msg_len, &h);
                            if (p_st != PKT_OK)
                            {
                                reject_packet(epfd, c, c->ei.fd, clients, &clients_count,
                                              "VALIDATE_PACKET_NAME ERROR", message_id++);
                                client_removed = 1;
                                continue;
                            }
                            if (rc == 0)
                            {
                                break;
                            }

                            if (h.type != PKT_NAME)
                            {
                                reject_packet(epfd, c, c->ei.fd, clients, &clients_count,
                                              "EXPECTED TYPE: PKT_NAME, RECEIVED", message_id++);
                                client_removed = 1;
                                continue;
                            }
                            if (is_name_taken(clients, clients_count, msg))
                            {
                                send_server_error(epfd, c, "NAME IS ALREADY TAKEN", message_id++);
                                continue;
                            }

                            set_client_name(c, msg, msg_len);
                            c->state = STATE_READY;

                            send_server_join(epfd, c, c->name, message_id++);
                            printf("[REGISTER] %s#%" PRIu32 "\n", c->name, c->id);

                            break;
                        case STATE_READY:
                            rc = recv_into_inbuf(c);
                            if (rc < 0)
                            {
                                if (rc == -2)
                                {
                                    perror("recv_into_buf PKT_CHAT");
                                }
                                disconnect_client(epfd, c, clients, &clients_count, message_id++);
                                client_removed = 1;
                                continue;
                            }
                            while (1)
                            {
                                Header h;
                                memset(&h, 0, sizeof(h));
                                rc = try_pop_packet(c, &h, msg, &msg_len);
                                if (rc == 0)
                                {
                                    break;
                                }
                                if (rc < 0)
                                {
                                    perror("try_pop_packet broadcast");
                                    remove_client(epfd, c->ei.fd, clients, &clients_count);
                                    client_removed = 1;
                                    break;
                                }
                                PacketState p_st = validate_packet_chat(msg_len, &h);
                                if (p_st == PKT_OK)
                                {
                                    Header out;
                                    memset(&out, 0, sizeof(out));
                                    out.version    = h.version;
                                    out.type       = h.type;
                                    out.flags      = h.flags;
                                    out.sender_id  = c->id;
                                    out.room_id    = 0;
                                    out.timestamp  = (uint64_t)time(NULL);
                                    out.message_id = message_id++;

                                    printf("%s#%" PRIu32 ": %.*s\n", c->name, c->id, (int)msg_len,
                                           msg);
                                    broadcast_message(epfd, c, &out, clients, &clients_count, msg,
                                                      msg_len);
                                }
                                else
                                {
                                    const char* p_st_str = packet_state_str(p_st);
                                    reject_packet(epfd, c, c->ei.fd, clients, &clients_count,
                                                  p_st_str, message_id++);
                                    client_removed = 1;
                                    break;
                                }
                            }
                            break;
                    }
                    if (client_removed)
                    {
                        break;
                    }
                }

                if (cur_evs & EPOLLOUT)
                {
                    int rc = flush_send(c);
                    if (rc < 0)
                    {
                        remove_client(epfd, c->ei.fd, clients, &clients_count);
                        client_removed = 1;
                        continue;
                    }
                    if (c->conn.out_len == 0)
                    {
                        if (unset_epollout_to_client(epfd, c) < 0)
                        {
                            remove_client(epfd, c->ei.fd, clients, &clients_count);
                            client_removed = 1;
                        }
                    }
                }
                if (client_removed)
                {
                    break;
                }
                // EPOLLHUP - соединение умерло полностью
                // EPOLLRDHUP - клиент больше не пишет, но может читать
                if (cur_evs & EPOLLHUP || cur_evs & EPOLLRDHUP || cur_evs & EPOLLERR)
                {
                    remove_client(epfd, c->ei.fd, clients, &clients_count);
                    client_removed = 1;
                    continue;
                }
            }
        }
    }

    for (int i = 0; i < clients_count; i++)
    {
        close(clients[i]->ei.fd);
    }
    close(server_fd);
    return 0;
}