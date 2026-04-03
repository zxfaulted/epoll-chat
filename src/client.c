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

// 0 некритичная ошибка, клиент может продолжат работу
// -1 критичная ошибка, закрыть клиент
static int handle_input(int epfd, Client* c, char* out_buf, ssize_t bytes)
{
    Header h;
    memset(&h, 0, sizeof(h));

    h.version    = 1;
    h.flags      = 0;
    h.sender_id  = 0;
    h.room_id    = 0;
    h.timestamp  = 0;
    h.message_id = 0;

    if (c->state == STATE_WAIT_REGISTER_OK)
    {
        return 0;
    }
    if (c->state == STATE_WAIT_NAME)
    {
        if (bytes == 0)
        {
            printf("[ERROR] EMPTY NAME\n");
            return 0;
        }
        if (bytes > MAX_NAME_LEN)
        {
            printf("[ERROR] NAME IS TOO LONG\n");
            return 0;
        }
        h.type = PKT_NAME;
        if (enqueue_packet(c, &h, (const uint8_t*)out_buf, bytes) < 0)
        {
            fprintf(stderr, "enqueue_packet failed\n");
            return -1;
        }
        if (set_epollout_to_client(epfd, c) < 0)
        {
            return -1;
        }
        c->state = STATE_WAIT_REGISTER_OK;
    }

    if (c->state == STATE_READY)
    {
        if (bytes == 0)
        {
            return 0;
        }
        if (bytes > PAYLOAD_SIZE)
        {
            printf("[ERROR] MESSAGE TOO LONG\n");
            return 0;
        }
        if (strncmp("/join ", out_buf, 6) == 0)
        {
            errno = 0;
            char*         end;
            unsigned long room = strtoul(out_buf + 6, &end, 0);
            if (*end != '\0')
            {
                printf("[ERROR] INVALID ROOM ID\n");
                return 0;
            }
            if (end == out_buf + 6)
            {
                printf("[ERROR] ROOM ID IS NOT A NUMBER\n");
                return 0;
            }
            if (errno == ERANGE)
            {
                printf("[ERROR] ROOM ID IS OUT OF RANGE\n");
                return 0;
            }
            h.type    = PKT_ROOM_CHANGE;
            h.room_id = (uint32_t)room;

            if (enqueue_packet(c, &h, NULL, 0) < 0)
            {
                fprintf(stderr, "enqueue_packet failed\n");
                return -1;
            }
            if (set_epollout_to_client(epfd, c) < 0)
            {
                return -1;
            }
        }
        else
        {
            h.type    = PKT_CHAT;
            h.room_id = c->room_id;
            if (enqueue_packet(c, &h, (const uint8_t*)out_buf, bytes) < 0)
            {
                fprintf(stderr, "enqueue_packet failed\n");
                return -1;
            }
            if (set_epollout_to_client(epfd, c) < 0)
            {
                return -1;
            }
        }
    }
    return 0;
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

    char stdin_line[BUF_SIZE];
    memset(stdin_line, 0, BUF_SIZE);
    size_t stdin_line_len  = 0;
    int    stdin_line_drop = 0;

    UserEntry ue[MAX_CLIENTS];
    memset(&ue, 0, sizeof(UserEntry) * MAX_CLIENTS);
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
                char read_buf[256];
                int  bytes = read(ei->fd, read_buf, sizeof(read_buf));
                if (bytes < 0)
                {
                    if (errno == EWOULDBLOCK || errno == EAGAIN)
                    {
                        continue;
                    }

                    perror("stdin read");
                    goto cleanup;
                }
                if (bytes == 0)
                {
                    printf("[INFO] STDIN CLOSED, EXITING CLIENT\n");
                    ret = 0;
                    goto cleanup;
                }
                if (bytes > 0)
                {

                    for (ssize_t j = 0; j < bytes; j++)
                    {
                        char ch = read_buf[j];
                        if (ch == '\n')
                        {
                            if (stdin_line_drop)
                            {
                                if (ch == '\n')
                                {
                                    stdin_line_drop = 0;
                                }
                                else
                                {
                                    continue;
                                }
                            }
                            if (stdin_line_len > 0 && stdin_line[stdin_line_len - 1] == '\r')
                            {
                                stdin_line_len--;
                            }
                            stdin_line[stdin_line_len] = '\0';

                            if (handle_input(epfd, c, stdin_line, stdin_line_len) < 0)
                            {
                                goto cleanup;
                            }
                            stdin_line_len = 0;
                            continue;
                        }
                        if (stdin_line_len + 1 >= sizeof(stdin_line))
                        {
                            printf("[ERROR] INPUT LINE TOO LONG\n");
                            stdin_line_len  = 0;
                            stdin_line_drop = 1;
                        }
                        stdin_line[stdin_line_len++] = ch;
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
                                if (add_user_entry(ue, joined_name, joined_id) < 0)
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
                            if (c->state == STATE_WAIT_REGISTER_OK)
                            {
                                char     my_name[MAX_NAME_LEN + 1];
                                uint32_t my_id         = 0;
                                uint32_t start_room_id = 0;
                                if (parse_client_register_ok(msg, msg_len, &my_id, &start_room_id,
                                                             my_name) < 0)
                                {
                                    continue;
                                }
                                c->state           = STATE_READY;
                                c->id              = my_id;
                                c->room_id         = start_room_id;
                                size_t my_name_len = strlen(my_name);
                                memcpy(c->name, my_name, my_name_len);
                                c->name[my_name_len] = '\0';
                                printf("[REGISTER] as %s#%" PRIu32 " in room%" PRIu32 "\n", c->name,
                                       c->id, c->room_id);
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
                            if (remove_user_entry_by_id(ue, left_id) < 0)
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
                                const char* name = find_user_name_by_id(ue, h.sender_id);
                                if (name == NULL)
                                {
                                }
                                printf("[room %" PRIu32 "] %s#%" PRIu32 ": %s\n", h.room_id,
                                       name ? name : "NULL", h.sender_id, out);
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
                        case PKT_ROOM_CHANGE_OK:
                        {
                            uint32_t prev_room = c->room_id;
                            c->room_id         = h.room_id;
                            printf("[ROOM CHANGE] You've changed your room from %" PRIu32
                                   " to %" PRIu32 "\n",
                                   prev_room, c->room_id);
                            memset(ue, 0, sizeof(ue[0]) * MAX_CLIENTS);
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
