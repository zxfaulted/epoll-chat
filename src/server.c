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
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1)
    {
        perror("setsockopt");
        close(server_fd);
        return 1;
    }

    if (bind(server_fd, (struct sockaddr*)&server_sa, server_len) < 0)
    {
        close(server_fd);
        perror("bind");
        return -1;
    }

    if (listen(server_fd, SOMAXCONN) < 0)
    {
        close(server_fd);
        perror("listen");
        return -1;
    }

    if (set_nonblocking(server_fd) < 0)
    {
        close(server_fd);
        return -1;
    }
    Server* server = malloc(sizeof(Server));
    if (server == NULL)
    {
        perror("server malloc");
        return -1;
    }
    server->sa = server_sa;

    server->ei.fd   = server_fd;
    server->ei.item = SERVER_ITEM;

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events   = EPOLLIN;
    ev.data.ptr = server;

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0)
    {
        perror("epoll_create1");
        close(server_fd);
        free(server);
        return -1;
    }
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, server->ei.fd, &ev) < 0)
    {
        perror("epoll ADD server");
        close(server_fd);
        close(epfd);
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
        if (nfds < 0)
        {
            perror("epoll_wait");
            break;
        }
        for (int i = 0; i < nfds; i++)
        {
            client_removed   = 0;
            uint32_t cur_evs = events[i].events;

            EpollItem* ei = events[i].data.ptr;

            // появился новый клиент
            if (ei->item == SERVER_ITEM)
            {
                // Server* s = (Server*)ei;
                if (add_new_client(epfd, server_fd, clients, &clients_count, &client_id) < 0)
                {
                    continue;
                }
            }
            else if (ei->item == CLIENT_ITEM)
            {
                Client* c = (Client*)ei;
                if (cur_evs & EPOLLIN)
                {
                    switch (c->state)
                    {
                        uint8_t  msg[PAYLOAD_SIZE];
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
                                fprintf(stderr, "recv_into_buf PKT_NAME");
                                if (disconnect_client(epfd, c, clients, &clients_count,
                                                      &message_id) < 0)
                                {
                                    fprintf(stderr, "FAILED TO DISCONNECT CLIENT\n");
                                }
                                client_removed = 1;
                                continue;
                            }
                            Header h = {0};
                            rc       = try_pop_packet(c, &h, msg, &msg_len);
                            if (rc == 0)
                            {
                                break;
                            }
                            if (rc < 0)
                            {
                                reject_packet(epfd, c, c->ei.fd, clients, &clients_count,
                                              "POP_PACKET_ERROR", &message_id);
                                client_removed = 1;
                                continue;
                            }

                            PacketState p_st = validate_packet_name(msg_len, &h);
                            if (p_st != PKT_OK)
                            {
                                char        res[100];
                                const char* p_st_str = packet_state_str(p_st);
                                snprintf(res, 100, "VALIDATE_PACKET_NAME ERROR: %s\n", p_st_str);

                                reject_packet(epfd, c, c->ei.fd, clients, &clients_count, res,
                                              &message_id);

                                client_removed = 1;
                                continue;
                            }

                            if (h.type != PKT_NAME)
                            {
                                reject_packet(epfd, c, c->ei.fd, clients, &clients_count,
                                              "EXPECTED TYPE: PKT_NAME, RECEIVED", &message_id);
                                client_removed = 1;
                                continue;
                            }

                            char out[MAX_NAME_LEN + 1];
                            memset(out, 0, sizeof(out));
                            if (payload_to_str(msg, msg_len, out, MAX_NAME_LEN + 1) < 0)
                            {
                                if (send_server_error(epfd, c, "NAME IS TOO LONG", &message_id) < 0)
                                {
                                    fprintf(stderr, "SEND_SERVER_ERROR FAILED\n");
                                    if (disconnect_client(epfd, c, clients, &clients_count,
                                                          &message_id) < 0)
                                    {
                                        fprintf(stderr, "DISCONNECT_CLIENT FAILED");
                                    }
                                    client_removed = 1;
                                }
                                continue;
                            }
                            size_t out_len = strlen(out);

                            if (is_name_taken(clients, clients_count, out, out_len))
                            {
                                if (send_server_error(epfd, c, "NAME IS ALREADY TAKEN",
                                                      &message_id) < 0)
                                {
                                    fprintf(stderr, "SEND_SERVER_ERROR FAILED\n");
                                }
                                continue;
                            }

                            if (set_client_name(c, out, out_len) < 0)
                            {
                                if (send_server_error(epfd, c, "COULDN'T SET CLIENT NAME",
                                                      &message_id) < 0)
                                {
                                    fprintf(stderr, "SEND_SERVER_ERROR FAILED\n");
                                }
                                continue;
                            }

                            if (send_server_user_event(c, PKT_REGISTER_OK, c->name, c->id,
                                                       &message_id) < 0)
                            {
                                fprintf(stderr, "COULDN'T SEND JOIN FOR CLIENT %s#%" PRIu32 "",
                                        c->name, c->id);
                                if (disconnect_client(epfd, c, clients, &clients_count,
                                                      &message_id) < 0)
                                {
                                    fprintf(stderr, "FAILED TO DISCONNECT CLIENT\n");
                                }
                                client_removed = 1;
                                continue;
                            }

                            if (set_epollout_to_client(epfd, c) < 0)
                            {
                                perror("set_epollout_to_client");
                                disconnect_client(epfd, c, clients, &clients_count, &message_id);
                                client_removed = 1;
                                continue;
                            }
                            c->state = STATE_READY;
                            broadcast_user_event(epfd, c, clients, &clients_count, PKT_JOIN,
                                                 &message_id);
                            printf("[REGISTER] %s#%" PRIu32 "\n", c->name, c->id);
                            if (send_server_ready_users(c, clients, clients_count, &message_id) < 0)
                            {
                                fprintf(stderr, "COULDN'T SEND READY USERS TO CHOSEN CLIENT");
                                if (disconnect_client(epfd, c, clients, &clients_count,
                                                      &message_id) < 0)
                                {
                                    fprintf(stderr, "FAILED TO DISCONNECT CLIENT\n");
                                }
                                client_removed = 1;
                                continue;
                            }
                            if (set_epollout_to_client(epfd, c) < 0)
                            {
                                perror("set_epollout_to_client");
                                disconnect_client(epfd, c, clients, &clients_count, &message_id);
                                client_removed = 1;
                                continue;
                            }
                            break;
                        case STATE_READY:
                            rc = recv_into_inbuf(c);
                            if (rc < 0)
                            {
                                if (rc == -2)
                                {
                                    perror("recv_into_buf PKT_CHAT");
                                }
                                if (disconnect_client(epfd, c, clients, &clients_count,
                                                      &message_id) < 0)
                                {
                                    fprintf(stderr, "FAILED TO DISCONNECT CLIENT\n");
                                }
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
                                    fprintf(stderr, "try_pop_packet broadcast");
                                    if (disconnect_client(epfd, c, clients, &clients_count,
                                                          &message_id) < 0)
                                    {
                                        fprintf(stderr, "FAILED TO DISCONNECT CLIENT\n");
                                    }
                                    client_removed = 1;
                                    continue;
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
                                    out.message_id = next_message_id(&message_id);

                                    printf("%s#%" PRIu32 ": %.*s\n", c->name, c->id, (int)msg_len,
                                           msg);
                                    broadcast_message(epfd, c, &out, clients, &clients_count, msg,
                                                      msg_len, &message_id);
                                }
                                else
                                {
                                    const char* p_st_str = packet_state_str(p_st);
                                    reject_packet(epfd, c, c->ei.fd, clients, &clients_count,
                                                  p_st_str, &message_id);
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
                        if (disconnect_client(epfd, c, clients, &clients_count, &message_id) < 0)
                        {
                            fprintf(stderr, "FAILED TO DISCONNECT CLIENT\n");
                        }
                        client_removed = 1;
                        continue;
                    }
                    if (c->conn.out_len == 0)
                    {
                        if (unset_epollout_to_client(epfd, c) < 0)
                        {
                            if (disconnect_client(epfd, c, clients, &clients_count, &message_id) <
                                0)
                            {
                                fprintf(stderr, "FAILED TO DISCONNECT CLIENT\n");
                            }
                            client_removed = 1;
                            continue;
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
                    if (disconnect_client(epfd, c, clients, &clients_count, &message_id) < 0)
                    {
                        fprintf(stderr, "FAILED TO DISCONNECT CLIENT\n");
                    }
                    client_removed = 1;
                    break;
                }
            }
        }
    }

    for (int i = 0; i < clients_count; i++)
    {
        close(clients[i]->ei.fd);
        free(clients[i]);
    }

    close(server_fd);
    close(epfd);
    free(server);

    return 0;
}