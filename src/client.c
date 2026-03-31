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

static int discard_stdin_until_newline(int fd)
{
    const int N = 256;
    uint8_t   tmp[N];
    while (1)
    {
        int bytes = read(fd, tmp, N);
        // EOF
        if (bytes == 0)
        {
            return 1;
        }
        if (bytes < 0)
        {
            // прерван сигналом
            if (errno == EINTR)
            {
                continue;
            }
            // данных больше нет
            if (errno == EWOULDBLOCK || errno == EAGAIN)
            {
                return 0;
            }
            perror("read");
            return -1;
        }
        for (int i = 0; i < bytes; i++)
        {
            if (tmp[i] == '\n')
            {
                return 0;
            }
        }
    }
    return -1;
}

int main()
{
    int        ret       = -1;
    int        client_fd = -1;
    int        epfd      = -1;
    Client*    c         = NULL;
    EpollItem* stdin     = NULL;
    signal(SIGPIPE, SIG_IGN);

    client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0)
    {
        perror("socket");
        goto cleanup;
    }

    struct sockaddr_in server_sa;
    socklen_t          server_len = sizeof(server_sa);
    memset(&server_sa, 0, server_len);
    int rc = inet_pton(AF_INET, SERVER_ADDRESS, &server_sa.sin_addr);
    if (rc == 0)
    {
        fprintf(stderr, "src does not contain a character string representing  a valid network "
                        "address in the specified address family\n");
        goto cleanup;
    }
    else if (rc < 0)
    {
        perror("inet_pton");
        goto cleanup;
    }

    server_sa.sin_family = AF_INET;
    server_sa.sin_port   = htons(SERVER_PORT);

    if (connect(client_fd, (struct sockaddr*)&server_sa, server_len) < 0)
    {
        perror("connect");
        goto cleanup;
    }

    if (set_nonblocking(client_fd) < 0)
    {
        goto cleanup;
    }
    epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0)
    {
        perror("epoll_create1");
        goto cleanup;
    }

    c = malloc(sizeof(Client));
    if (c == NULL)
    {
        perror("Client* c malloc");
        goto cleanup;
    }
    memset(c, 0, sizeof(Client));
    c->ei.fd   = client_fd;
    c->ei.item = CLIENT_ITEM;
    c->state   = STATE_WAIT_NAME;

    struct epoll_event ev;
    ev.data.ptr = c;
    ev.events   = EPOLLIN | EPOLLHUP | EPOLLRDHUP | EPOLLERR;

    if (epoll_ctl(epfd, EPOLL_CTL_ADD, c->ei.fd, &ev) < 0)
    {
        perror("epoll_ctl add client");
        goto cleanup;
    }

    stdin = malloc(sizeof(EpollItem));
    if (stdin == NULL)
    {
        perror("EpollItem* stdin malloc");
        goto cleanup;
    }
    stdin->fd   = STDIN_FILENO;
    stdin->item = STDIN_ITEM;
    ev.data.ptr = stdin;
    ev.events   = EPOLLIN;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, STDIN_FILENO, &ev) < 0)
    {
        perror("epoll_ctl add stdin");
        goto cleanup;
    }

    struct epoll_event events[2];
    memset(events, 0, sizeof(events));

    char out[OUT_CAP];
    memset(out, 0, sizeof(out));
    while (1)
    {
        int nfds = epoll_wait(epfd, events, 2, -1);
        if (nfds < 0)
        {
            perror("epoll_wait");
            goto cleanup;
        }
        for (int i = 0; i < nfds; i++)
        {
            uint32_t   cur_evs = events[i].events;
            EpollItem* ei      = (EpollItem*)events[i].data.ptr;

            if (ei->item == STDIN_ITEM && cur_evs & EPOLLIN)
            {
                char out_buf[PAYLOAD_SIZE + 1];
                memset(&out_buf, 0, sizeof(out_buf));
                int bytes = read(ei->fd, out_buf, sizeof(out_buf));
                if (bytes < 0)
                {
                    if (errno == EWOULDBLOCK || errno == EAGAIN)
                    {
                        continue;
                    }
                    else
                    {
                        perror("stdin read");
                        goto cleanup;
                    }
                }
                if (bytes == 0)
                {
                    printf("[INFO] STDIN CLOSED, EXITING CLIENT\n");
                    ret = 0;
                    goto cleanup;
                }
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
                        h.sender_id  = 0;
                        h.room_id    = 0;
                        h.timestamp  = 0;
                        h.message_id = 0;

                        switch (c->state)
                        {
                            case STATE_WAIT_NAME:
                            {
                                if (bytes == 0)
                                {
                                    printf("[ERROR] EMPTY NAME\n");
                                    continue;
                                }
                                if (bytes > MAX_NAME_LEN)
                                {
                                    printf("[ERROR] NAME IS TOO LONG\n");
                                    int drc = discard_stdin_until_newline(stdin->fd);
                                    if (drc < 0)
                                    {
                                        ret = -1;
                                        goto cleanup;
                                    }
                                    if (drc > 0)
                                    {
                                        ret = 0;
                                        goto cleanup;
                                    }
                                    continue;
                                }
                                h.type = PKT_NAME;
                                break;
                            }

                            case STATE_READY:
                            {
                                if (bytes == 0)
                                {
                                    continue;
                                }
                                if (bytes > PAYLOAD_SIZE)
                                {
                                    printf("[ERROR] MESSAGE TOO LONG\n");
                                    int drc = discard_stdin_until_newline(stdin->fd);
                                    if (drc < 0)
                                    {
                                        ret = -1;
                                        goto cleanup;
                                    }
                                    if (drc > 0)
                                    {
                                        ret = 0;
                                        goto cleanup;
                                    }
                                    continue;
                                }
                                h.type = PKT_CHAT;
                                break;
                            }
                        }
                        if (enqueue_packet(c, &h, (const uint8_t*)out_buf, bytes) < 0)
                        {
                            continue;
                        }
                        if (set_epollout_to_client(epfd, c) < 0)
                        {
                            goto cleanup;
                        }
                    }
                }
            }

            if ((ei->item == CLIENT_ITEM) && (cur_evs & EPOLLIN))
            {
                Client*  c = (Client*)ei;
                uint8_t  msg[PAYLOAD_SIZE];
                uint32_t msg_len = 0;

                while (1)
                {
                    int rc = recv_into_inbuf(c);
                    if (rc == -1)
                    {
                        ret = 0;
                        goto cleanup;
                    }
                    if (rc == -2)
                    {
                        ret = -1;
                        goto cleanup;
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
                        goto cleanup;
                    }
                    else if (rc == 0)
                    {
                        break;
                    }
                    switch (h.type)
                    {
                        case PKT_JOIN:
                        {

                            if (c->state == STATE_READY)
                            {
                                char     joined_name[MAX_NAME_LEN + 1];
                                uint32_t joined_id = 0;
                                if (parse_client_id_and_name(msg, msg_len, &joined_id,
                                                             joined_name) < 0)
                                {
                                    continue;
                                }
                                size_t joined_name_len = strlen(joined_name);
                                printf("[JOIN] %.*s#%" PRIu32 "\n", (int)joined_name_len,
                                       joined_name, joined_id);
                            }
                            break;
                        }
                        case PKT_REGISTER_OK:
                        {
                            if (c->state != STATE_READY)
                            {
                                char     my_name[MAX_NAME_LEN + 1];
                                uint32_t my_id = 0;
                                if (parse_client_id_and_name(msg, msg_len, &my_id, my_name) < 0)
                                {
                                    continue;
                                }
                                c->state           = STATE_READY;
                                c->id              = my_id;
                                size_t my_name_len = strlen(my_name);
                                memcpy(c->name, my_name, my_name_len);
                                c->name[my_name_len] = '\0';
                                printf("[REGISTER] as %s#%" PRIu32 "\n", c->name, c->id);
                            }
                            break;
                        }

                        case PKT_LEAVE:
                        {
                            uint32_t left_id;
                            char     left_name[MAX_NAME_LEN + 1];
                            if (parse_client_id_and_name(msg, msg_len, &left_id, left_name) < 0)
                            {
                                continue;
                            }
                            size_t left_name_len = strlen(left_name);
                            printf("[LEAVE] %.*s#%" PRIu32 "\n", (int)left_name_len, left_name,
                                   left_id);
                            break;
                        }

                        case PKT_CHAT:
                        {
                            memset(out, 0, sizeof(out));
                            if (payload_to_str(msg, msg_len, out, OUT_CAP) == 0)
                            {
                                printf("#%" PRIu32 ": %s\n", h.sender_id, out);
                            }
                            break;
                        }
                        case PKT_ERR:
                        {
                            memset(out, 0, sizeof(out));
                            if (payload_to_str(msg, msg_len, out, OUT_CAP) == 0)
                            {
                                printf("[ERROR] %s\n", out);
                            }
                            break;
                        }
                        default:
                        {
                            const char* p_t = packet_type_str(h.type);
                            printf("[ERROR] UNKNOWN PACKET TYPE: %s\n", p_t);
                            break;
                        }
                    }
                }
            }

            if ((ei->item == CLIENT_ITEM) && cur_evs & EPOLLOUT)
            {
                Client* c  = (Client*)ei;
                int     rc = flush_send(c);
                if (rc < 0)
                {
                    goto cleanup;
                }
                else if (c->conn.out_len == 0)
                {
                    if (unset_epollout_to_client(epfd, c) < 0)
                    {

                        goto cleanup;
                    }
                }
                else if (rc == 0)
                {
                    continue;
                }
            }
            if (cur_evs & EPOLLHUP || cur_evs & EPOLLRDHUP || cur_evs & EPOLLERR)
            {
                if ((cur_evs & EPOLLERR) != 0)
                {
                    ret = -1;
                    goto cleanup;
                }
                if ((cur_evs & EPOLLHUP) != 0 || (cur_evs & EPOLLRDHUP) != 0)
                {
                    ret = 0;
                    goto cleanup;
                }
            }
        }
    }

    ret = 0;
cleanup:
    if (client_fd >= 0)
    {
        close(client_fd);
    }
    if (epfd >= 0)
    {
        close(epfd);
    }
    free(stdin);
    free(c);
    return ret;
}
