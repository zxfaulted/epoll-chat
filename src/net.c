#include "net.h"
#include "auth.h"
#include "crypto.h"
#include "room.h"
#include "transport.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

// strnlen из <string.h> не входит в ISO C11
// для возможности сборки с -std=c11
// static size_t my_strnlen(const char* s, size_t maxlen)
// {
//     size_t i;
//     for (i = 0; i < maxlen && s[i] != '\0'; i++)
//     {
//     }
//     return i;
// }

uint32_t next_message_id(uint32_t* message_id)
{
    return ++(*message_id);
}

int payload_to_str(const uint8_t payload[], size_t len, char out[], size_t out_cap)
{
    if ((size_t)len + 1 > out_cap)
    {
        return -1;
    }
    memcpy(out, payload, len);
    out[len] = '\0';
    return 0;
}

static void remove_client(int epfd, int cur_fd, Client* clients[], int* clients_count)
{

    for (int i = 0; i < *clients_count; i++)
    {
        if (clients[i] && clients[i]->ei.fd == cur_fd)
        {
            Client* temp                = clients[i];
            clients[i]                  = clients[*clients_count - 1];
            clients[*clients_count - 1] = NULL;
            (*clients_count)--;

            printf("[DISCONNECT] Client #%" PRIu32 "\n", temp->id);

            if (epoll_ctl(epfd, EPOLL_CTL_DEL, cur_fd, NULL) < 0)
            {
                perror("epoll_ctl DEL");
            }
            close(cur_fd);
            OPENSSL_free(temp->raw_kb);
            free(temp);
            break;
        }
    }
}

void reject_packet(int epfd, Client* c, int cur_fd, Client* clients[], int* clients_count,
                   const char* reason, uint32_t* message_id)
{
    fprintf(stderr, "[REJECT] fd=%d reason=%s\n", cur_fd, reason);
    disconnect_client(epfd, c, clients, clients_count, message_id);
}

PacketState validate_packet_name(uint32_t msg_len, Header* h)
{
    if (h->version != 1)
    {
        return PKT_BAD_VERSION;
    }
    if (h->type != PKT_NAME && h->type != PKT_REGISTER_BEGIN)
    {
        return PKT_BAD_TYPE;
    }
    if (h->flags != 0)
    {
        return PKT_BAD_FLAGS;
    }
    if (h->sender_id != 0)
    {
        return PKT_BAD_SENDER_ID;
    }
    if (h->room_id != 0)
    {
        return PKT_BAD_ROOM_ID;
    }
    if (h->timestamp != 0)
    {
        return PKT_BAD_TIMESTAMP;
    }
    if (h->message_id != 0)
    {
        return PKT_BAD_MESSAGE_ID;
    }
    if (msg_len == 0 || msg_len > MAX_NAME_LEN)
    {
        return PKT_BAD_PAYLOAD_SIZE;
    }
    return PKT_OK;
}

PacketState validate_packet_chat(uint32_t msg_len, Header* h)
{
    if (h->version != 1)
    {
        return PKT_BAD_VERSION;
    }
    if (h->type != PKT_CHAT)
    {
        return PKT_BAD_TYPE;
    }
    if (h->flags != 0)
    {
        return PKT_BAD_FLAGS;
    }
    if (h->room_id == 0 || h->room_id > MAX_ROOMS)
    {
        return PKT_BAD_ROOM_ID;
    }
    if (h->timestamp != 0)
    {
        return PKT_BAD_TIMESTAMP;
    }
    if (h->sender_id != 0)
    {
        return PKT_BAD_SENDER_ID;
    }
    if (h->message_id != 0)
    {
        return PKT_BAD_MESSAGE_ID;
    }
    if (msg_len == 0 || msg_len > PAYLOAD_SIZE)
    {
        return PKT_BAD_PAYLOAD_SIZE;
    }
    return PKT_OK;
}

PacketState validate_packet_room_change(uint32_t msg_len, Header* h)
{
    if (h->version != 1)
    {
        return PKT_BAD_VERSION;
    }
    if (h->type != PKT_ROOM_CHANGE)
    {
        return PKT_BAD_TYPE;
    }
    if (h->flags != 0)
    {
        return PKT_BAD_FLAGS;
    }
    if (h->room_id == 0 || h->room_id > MAX_ROOMS)
    {
        return PKT_BAD_ROOM_ID;
    }
    if (h->timestamp != 0)
    {
        return PKT_BAD_TIMESTAMP;
    }
    if (h->sender_id != 0)
    {
        return PKT_BAD_SENDER_ID;
    }
    if (h->message_id != 0)
    {
        return PKT_BAD_MESSAGE_ID;
    }
    if ((msg_len == 0 && h->type != PKT_ROOM_CHANGE) ||
        (h->type == PKT_ROOM_CHANGE && msg_len != 0) || msg_len > PAYLOAD_SIZE)
    {
        return PKT_BAD_PAYLOAD_SIZE;
    }
    return PKT_OK;
}

int add_new_client(int epfd, int server_fd, Client* clients[], int* clients_count,
                   uint32_t* client_id)
{
    while (1)
    {
        if ((*clients_count) >= MAX_CLIENTS)
        {
            fprintf(stderr, "too many clients");
            return -1;
        }
        struct sockaddr_in new_client_sa;
        socklen_t          new_client_len = sizeof(new_client_sa);
        memset(&new_client_sa, 0, new_client_len);
        int new_client_fd = accept(server_fd, (struct sockaddr*)&new_client_sa, &new_client_len);
        if (new_client_fd < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                return 0;
            }
            return -1;
        }

        if (set_nonblocking(new_client_fd) < 0)
        {
            close(new_client_fd);
            return -1;
        }

        Client* new_client = malloc(sizeof(Client));
        if (!new_client)
        {
            close(new_client_fd);
            return -1;
        }
        memset(new_client, 0, sizeof(Client));
        new_client->id      = (*client_id)++;
        new_client->sa      = new_client_sa;
        new_client->ei.item = CLIENT_ITEM;
        new_client->ei.fd   = new_client_fd;
        new_client->state   = STATE_WAIT_NAME;
        new_client->name[0] = '\0';
        new_client->room_id = 1;

        struct epoll_event ev;
        ev.events   = EPOLLIN | EPOLLHUP | EPOLLRDHUP;
        ev.data.ptr = new_client;

        if (epoll_ctl(epfd, EPOLL_CTL_ADD, new_client_fd, &ev) < 0)
        {
            perror("epoll_ctl ADD new_client");
            close(new_client_fd);
            free(new_client);
            return -1;
        };
        clients[(*clients_count)++] = new_client;

        printf("[CONNECT] Client #%" PRIu32 "\n", new_client->id);
    }
}

int set_client_name(Client* c, const char* msg, size_t msg_len)
{
    if (msg_len == 0 || msg_len > MAX_NAME_LEN)
    {
        return -1;
    }

    memcpy(c->name, msg, msg_len);
    c->name[msg_len] = '\0';

    return 0;
}

int is_name_taken(Client* clients[], int clients_count, const char* name, size_t name_len)
{
    for (int i = 0; i < clients_count; i++)
    {
        if ((clients[i] && clients[i]->state == STATE_READY) &&
            (strlen(clients[i]->name) == name_len) &&
            (memcmp(clients[i]->name, name, name_len) == 0))
        {
            return 1;
        }
    }
    return 0;
}

void broadcast_message(int epfd, Client* c, Header* h, Client* clients[], int* clients_count,
                       const uint8_t msg[], uint32_t len, uint32_t* message_id)
{

    int i = 0;
    while (i < *clients_count)
    {
        if (clients[i]->ei.fd == c->ei.fd)
        {
            i++;
            continue;
        }

        if (clients[i]->state != STATE_READY)
        {
            i++;
            continue;
        }
        if (clients[i]->room_id != h->room_id)
        {
            i++;
            continue;
        }
        if (enqueue_packet(clients[i], h, msg, len) < 0)
        {
            i++;
            continue;
        }
        // без i++ для учета swap-delete
        if (set_epollout_to_client(epfd, clients[i]) < 0)
        {
            perror("set_epollout_to_client");
            disconnect_client(epfd, clients[i], clients, clients_count, message_id);
            continue;
        }
        i++;
    }
}

int send_server_user_event(Client* c, uint32_t room_id, PacketType type, const char* name,
                           uint32_t user_id, uint32_t* message_id)
{
    if (type != PKT_JOIN && type != PKT_LEAVE && type != PKT_REGISTER_OK &&
        type != PKT_ROOM_CHANGE_OK && type != PKT_ROOM_SYNC_DONE)
    {
        return -1;
    }
    if (!c || !name)
    {
        return -1;
    }
    Header h;
    memset(&h, 0, sizeof(h));
    h.flags      = 0;
    h.message_id = next_message_id(message_id);
    h.room_id    = room_id;
    h.sender_id  = SERVER_ID;
    h.timestamp  = (uint64_t)time(NULL);
    h.type       = type;
    h.version    = 1;

    size_t  name_len = strlen(name);
    uint8_t msg[PAYLOAD_ID_AND_NAME_SIZE];

    uint32_t msg_len = SENDER_ID_SIZE + name_len;
    if (msg_len > PAYLOAD_ID_AND_NAME_SIZE)
    {
        return -1;
    }

    uint32_t net_user_id = htonl(user_id);
    size_t   off         = 0;
    memcpy(msg + off, &net_user_id, SENDER_ID_SIZE);
    off += SENDER_ID_SIZE;
    memcpy(msg + off, name, name_len);

    return enqueue_packet(c, &h, msg, msg_len);
}

int send_server_register_ok(Client* c, uint32_t room_id, const char* name, uint32_t user_id,
                            uint32_t* message_id)
{

    if (!c || !name || !message_id)
    {
        return -1;
    }
    Header h;
    memset(&h, 0, sizeof(h));
    h.flags      = 0;
    h.message_id = next_message_id(message_id);
    h.room_id    = room_id;
    h.sender_id  = SERVER_ID;
    h.timestamp  = (uint64_t)time(NULL);
    h.type       = PKT_REGISTER_OK;
    h.version    = 1;

    size_t  name_len = strlen(name);
    uint8_t msg[PAYLOAD_REGISTER_OK_SIZE];

    uint32_t msg_len = SENDER_ID_SIZE + ROOM_ID_SIZE + name_len;
    if (msg_len > PAYLOAD_REGISTER_OK_SIZE)
    {
        return -1;
    }

    uint32_t net_user_id = htonl(user_id);
    uint32_t net_room_id = htonl(room_id);
    size_t   off         = 0;
    memcpy(msg + off, &net_user_id, SENDER_ID_SIZE);
    off += SENDER_ID_SIZE;
    memcpy(msg + off, &net_room_id, ROOM_ID_SIZE);
    off += ROOM_ID_SIZE;
    memcpy(msg + off, name, name_len);

    return enqueue_packet(c, &h, msg, msg_len);
}

void broadcast_user_event(int epfd, Client* skip, uint32_t room_id, Client* clients[],
                          int* clients_count, PacketType type, uint32_t* message_id)
{
    if (!skip || !clients || !clients_count || !message_id)
    {
        return;
    }
    uint32_t skip_id                     = skip->id;
    char     skip_name[MAX_NAME_LEN + 1] = {0};
    memcpy(skip_name, skip->name, MAX_NAME_LEN);
    skip_name[MAX_NAME_LEN] = '\0';

    int i = 0;
    while (i < *clients_count)
    {
        if (clients[i] == skip || clients[i]->id == skip_id)
        {
            i++;
            continue;
        }

        if (clients[i]->state != STATE_READY)
        {
            i++;
            continue;
        }
        if (clients[i]->room_id != room_id)
        {
            i++;
            continue;
        }
        if (send_server_user_event(clients[i], room_id, type, skip_name, skip_id, message_id) < 0)
        {
            i++;
            continue;
        }
        // если сервер не смог включить epollout, значит, не может надежно обслуживать соединение
        // поэтому его закрываем
        if (set_epollout_to_client(epfd, clients[i]) < 0)
        {
            perror("set_epollout_to_client");
            disconnect_client(epfd, clients[i], clients, clients_count, message_id);
            continue;
        }
        i++;
    }
}

int disconnect_client(int epfd, Client* c, Client* clients[], int* clients_count,
                      uint32_t* message_id)
{
    if (!c || !clients)
    {
        return -1;
    }
    if (c->state == STATE_READY && c->name[0] != '\0')
    {
        broadcast_user_event(epfd, c, c->room_id, clients, clients_count, PKT_LEAVE, message_id);
    }
    remove_client(epfd, c->ei.fd, clients, clients_count);
    return 0;
}

int send_server_error(int epfd, Client* c, const char msg[], uint32_t* message_id)
{
    Header h;
    memset(&h, 0, sizeof(h));
    h.version    = 1;
    h.flags      = 0;
    h.message_id = next_message_id(message_id);
    h.type       = PKT_ERR;
    h.room_id    = 0;
    h.sender_id  = 0;
    h.timestamp  = (uint64_t)time(NULL);

    if (enqueue_packet(c, &h, (const uint8_t*)msg, (uint32_t)strlen(msg)) < 0)
    {
        return -1;
    }
    if (set_epollout_to_client(epfd, c) < 0)
    {
        return -1;
    }
    return 0;
}

int parse_client_register_ok(const uint8_t* msg, uint32_t msg_len, uint32_t* client_id,
                             uint32_t* room_id, char name[])
{
    if (!msg || !client_id || !name || !room_id)
    {
        return -1;
    }
    if (msg_len < SENDER_ID_SIZE + ROOM_ID_SIZE)
    {
        return -1;
    }
    size_t off = 0;
    memcpy(client_id, msg + off, SENDER_ID_SIZE);
    *(client_id) = ntohl(*client_id);
    off += SENDER_ID_SIZE;

    memcpy(room_id, msg + off, ROOM_ID_SIZE);
    *(room_id) = ntohl(*room_id);
    off += ROOM_ID_SIZE;

    size_t name_len = msg_len - off;
    if (name_len > MAX_NAME_LEN)
    {
        return -1;
    }
    memcpy(name, msg + off, name_len);
    name[name_len] = '\0';
    return 0;
}

int parse_client_id_and_name(const uint8_t* msg, uint32_t msg_len, uint32_t* client_id, char name[])
{
    if (!msg || !client_id || !name)
    {
        return -1;
    }
    if (msg_len < SENDER_ID_SIZE)
    {
        return -1;
    }
    size_t off = 0;
    memcpy(client_id, msg + off, SENDER_ID_SIZE);
    *(client_id) = ntohl(*client_id);
    off += SENDER_ID_SIZE;

    size_t name_len = msg_len - off;
    if (name_len > MAX_NAME_LEN)
    {
        return -1;
    }
    memcpy(name, msg + off, name_len);
    name[name_len] = '\0';
    return 0;
}

int send_server_ready_users(Client* c, uint32_t room_id, Client* clients[], int clients_count,
                            uint32_t* message_id)
{
    if (!c || !clients)
    {
        return -1;
    }
    for (int i = 0; i < clients_count; i++)
    {
        if (clients[i] && clients[i]->state == STATE_READY && c != clients[i] &&
            clients[i]->room_id == room_id)
        {
            if (send_server_user_event(c, room_id, PKT_JOIN, clients[i]->name, clients[i]->id,
                                       message_id) < 0)
            {
                return -1;
            }
        }
    }
    return 0;
}

Client* find_client(Client* clients[], int clients_count, uint32_t client_id)
{
    for (int i = 0; i < clients_count; i++)
    {
        if (clients[i] && clients[i]->id == client_id)
        {
            return clients[i];
        }
    }
    return NULL;
}

// [2 identity_pub_der_len]
// [identity_pub_der]
// [2 signature_len]
// [signature]
int client_send_pkt_register_commit(int epfd, Client* c, uint8_t* identity_pub_der,
                                    uint16_t identity_pub_der_len, uint8_t* sig, uint16_t siglen)
{
    int    ret   = -1;
    Header h     = {0};
    h.flags      = 0;
    h.message_id = 0;
    h.room_id    = c->room_id;
    h.sender_id  = c->id;
    h.timestamp  = (uint64_t)time(NULL);
    h.type       = PKT_REGISTER_COMMIT;
    h.version    = 1;

    uint32_t out_buf_len = 2 + identity_pub_der_len + 2 + siglen;
    uint8_t* out_buf     = OPENSSL_malloc(out_buf_len);
    if (!out_buf)
    {
        ossl_print_error("OPENSSL_malloc");
        return -1;
    }
    uint8_t* p   = out_buf;
    size_t   off = 0;

    put_u16_be(p + off, identity_pub_der_len);
    off += 2;
    memcpy(p + off, identity_pub_der, identity_pub_der_len);
    off += identity_pub_der_len;
    put_u16_be(p + off, siglen);
    off += 2;
    memcpy(p + off, sig, siglen);

    if (enqueue_packet(c, &h, out_buf, out_buf_len) < 0)
    {
        fprintf(stderr, "enqueue_packet");
        goto cleanup;
    }
    if (set_epollout_to_client(epfd, c) < 0)
    {
        fprintf(stderr, "enqueue_packet");
        goto cleanup;
    }
    ret = 0;
cleanup:
    OPENSSL_free(out_buf);
    return ret;
}

int send_name_command(int epfd, Client* c, uint8_t pkt_type, const char* user_name)
{
    size_t name_len = strlen(user_name);

    if (name_len == 0)
    {
        printf("[ERROR] EMPTY NAME\n");
        return 0;
    }

    if (name_len > MAX_NAME_LEN)
    {
        printf("[ERROR] NAME IS TOO LONG\n");
        return 0;
    }

    Header h;
    memset(&h, 0, sizeof(h));

    h.version    = 1;
    h.flags      = 0;
    h.sender_id  = 0;
    h.room_id    = 0;
    h.timestamp  = 0;
    h.message_id = 0;
    h.type       = pkt_type;

    if (enqueue_packet(c, &h, (const uint8_t*)user_name, name_len) < 0)
    {
        fprintf(stderr, "enqueue_packet failed\n");
        return -1;
    }

    if (set_epollout_to_client(epfd, c) < 0)
    {
        return -1;
    }

    memset(c->name, 0, sizeof(c->name));
    memcpy(c->name, user_name, name_len);
    c->name[name_len] = '\0';

    if (pkt_type == PKT_REGISTER_BEGIN)
    {
        c->state = STATE_WAIT_REGISTER_CHALLENGE;
    }
    else if (pkt_type == PKT_NAME)
    {
        c->state = STATE_WAIT_AUTH_CHALLENGE;
    }

    return 0;
}

void print_help(Client* c)
{
    if (!c || c->state != STATE_READY)
    {
        printf("Commands before login:\n");
        printf("  /help\n");
        printf("  /register NAME\n");
        printf("  /login NAME\n");
        printf("\n");
        printf("You are not in chat yet. Plain text will not be sent.\n");
        return;
    }

    printf("Commands:\n");
    printf("  /help\n");
    printf("  /join ROOM_ID\n");
    printf("\n");
    printf("Plain text is sent to the current room.\n");
}

// 0 некритичная ошибка, клиент может продолжат работу
// -1 критичная ошибка, закрыть клиент
int handle_input(int epfd, Client* c, RoomSession* rooms, GeneratedKeys* gk, char* out_buf,
                 ssize_t bytes, const char* default_name, int* registration_in_progress,
                 int* generated_keys_for_registration)
{
    Header h;
    memset(&h, 0, sizeof(h));

    h.version    = 1;
    h.flags      = 0;
    h.sender_id  = 0;
    h.room_id    = 0;
    h.timestamp  = 0;
    h.message_id = 0;

    if (bytes == 0)
    {
        return 0;
    }
    if (strcmp(out_buf, "/help") == 0)
    {
        print_help(c);
        return 0;
    }

    if (c->state == STATE_WAIT_NAME)
    {
        if (strncmp(out_buf, "/register ", 10) == 0)
        {
            const char* reg_name = out_buf + 10;

            if (reg_name[0] == '\0')
            {
                printf("[ERROR] Usage: /register NAME\n");
                return 0;
            }

            if (strlen(reg_name) > MAX_NAME_LEN)
            {
                printf("[ERROR] NAME IS TOO LONG\n");
                return 0;
            }

            clear_generated_keys(gk);

            if (keys_exist(reg_name) == 1)
            {
                if (load_keys_for_name(gk, reg_name) < 0)
                {
                    printf("[ERROR] Failed to load local keys for '%s'\n", reg_name);
                    return 0;
                }

                *generated_keys_for_registration = 0;
            }
            else
            {
                gk->identity_private = NULL;
                gk->vko_private      = NULL;

                *generated_keys_for_registration = 0;
            }

            *registration_in_progress = 1;

            return send_name_command(epfd, c, PKT_REGISTER_BEGIN, reg_name);
        }

        if (strcmp(out_buf, "/register") == 0)
        {
            if (strlen(default_name) > MAX_NAME_LEN)
            {
                printf("[ERROR] NAME IS TOO LONG\n");
                return 0;
            }

            clear_generated_keys(gk);

            if (keys_exist(default_name) == 1)
            {
                if (load_keys_for_name(gk, default_name) < 0)
                {
                    printf("[ERROR] Failed to load local keys for '%s'\n", default_name);
                    return 0;
                }

                *generated_keys_for_registration = 0;
            }

            *registration_in_progress = 1;

            return send_name_command(epfd, c, PKT_REGISTER_BEGIN, default_name);
        }

        if (strncmp(out_buf, "/login ", 7) == 0)
        {
            const char* login_name = out_buf + 7;

            if (login_name[0] == '\0')
            {
                printf("[ERROR] Usage: /login NAME\n");
                return 0;
            }

            if (strlen(login_name) > MAX_NAME_LEN)
            {
                printf("[ERROR] NAME IS TOO LONG\n");
                return 0;
            }

            if (keys_exist(login_name) != 1)
            {
                printf("[ERROR] No local keys for '%s'. Use /register %s first.\n", login_name,
                       login_name);
                return 0;
            }

            if (load_keys_for_name(gk, login_name) < 0)
            {
                printf("[ERROR] Failed to load local keys for '%s'\n", login_name);
                return 0;
            }

            *registration_in_progress        = 0;
            *generated_keys_for_registration = 0;

            return send_name_command(epfd, c, PKT_NAME, login_name);
        }

        if (strcmp(out_buf, "/login") == 0)
        {
            if (keys_exist(default_name) != 1)
            {
                printf("[ERROR] No local keys for '%s'. Use /register %s first.\n", default_name,
                       default_name);
                return 0;
            }

            if (load_keys_for_name(gk, default_name) < 0)
            {
                printf("[ERROR] Failed to load local keys for '%s'\n", default_name);
                return 0;
            }

            *registration_in_progress        = 0;
            *generated_keys_for_registration = 0;

            return send_name_command(epfd, c, PKT_NAME, default_name);
        }

        if (out_buf[0] == '/')
        {
            printf("[ERROR] Unknown command: %s\n", out_buf);
            printf("[LOCAL] Type /help to see supported commands.\n");
            return 0;
        }

        printf("[LOCAL] Message was not sent. You are not logged in.\n");
        printf("[LOCAL] Use '/login NAME' or '/register NAME'.\n");
        printf("[LOCAL] Use '/login' or '/register' to use your %s.\n", default_name);
        return 0;
    }

    if (c->state != STATE_READY)
    {
        if (out_buf[0] == '/')
        {
            printf("[LOCAL] Command cannot be used right now. Waiting for server response.\n");
        }
        else
        {
            printf("[LOCAL] Message was not sent. You are not ready yet.\n");
        }

        return 0;
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
            if (room == 0 || room > MAX_ROOMS)
            {
                printf("[ERROR] INVALID ROOM ID\n");
                return 0;
            }

            if ((uint32_t)room == c->room_id)
            {
                printf("[LOCAL] You are already in room #%" PRIu32 "\n", c->room_id);
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
            h.type            = PKT_ENC_CHAT;
            h.room_id         = c->room_id;
            RoomSession* room = find_room_session(rooms, MAX_ROOMS, c->room_id);
            if (!room)
            {
                fprintf(stderr, "[E2E] no room key for room#%" PRIu32 "\n", c->room_id);
                return 0;
            }
            if (bytes < 0 || bytes > UINT16_MAX)
            {
                fprintf(stderr, "message is too large\n");
                return -1;
            }
            if (client_send_pkt_enc_chat(epfd, c, room, (uint8_t*)out_buf, (uint16_t)bytes) < 0)
            {
                fprintf(stderr, "enqueue_packet failed\n");
                return -1;
            }
            printf("[room #%" PRIu32 "] %s: %s\n", c->room_id, c->name, out_buf);
            if (set_epollout_to_client(epfd, c) < 0)
            {
                return -1;
            }
        }
    }
    return 0;
}

// void remove_room_session(RoomSession* rooms, size_t rooms_count, uint32_t room_id)
// {
//     for (size_t i = 0; i < rooms_count; i++)
//     {
//         if (rooms[i].used && rooms[i].room_id == room_id)
//         {
//             OPENSSL_cleanse(&rooms[i], sizeof(rooms[i]));
//             return;
//         }
//     }
// }

// PKT_ENC_CHAT
// [1  enc_version]
// [1  suite]
// [2  reserved]
// [8  room_epoch]
// [8  seq]
// [16 nonce]
// [N  ciphertext]
// [16 tag]
int client_send_pkt_enc_chat(int epfd, Client* c, RoomSession* room, uint8_t* msg, uint16_t msg_len)
{
    if (!c || !room || !msg || msg_len > ENC_PLAINTEXT_MAX_LEN)
    {
        return -1;
    }
    int    ret            = -1;
    Header h              = {0};
    h.flags               = 0;
    h.message_id          = 0;
    h.room_id             = room->room_id;
    h.sender_id           = c->id;
    h.type                = PKT_ENC_CHAT;
    h.version             = 1;
    h.timestamp           = (uint64_t)time(NULL);
    uint8_t* enc_msg      = NULL;
    uint16_t enc_msg_len  = 0;
    uint8_t* tag          = NULL;
    uint16_t tag_len      = 0;
    uint8_t* pkt_enc_chat = NULL;
    uint8_t* p            = NULL;
    uint8_t* nonce        = NULL;

    if (encrypt_chat_message(room->room_key, c->id, c->room_id, room->epoch, room->send_seq, msg,
                             msg_len, &enc_msg, &enc_msg_len, &tag, &tag_len, &nonce) < 0)
    {
        fprintf(stderr, "encrypt_chat_message failed\n");
        goto cleanup;
    }
    if (enc_msg_len > ENC_PLAINTEXT_MAX_LEN)
    {
        fprintf(stderr, "enc_msg_len too large\n");
        goto cleanup;
    }
    pkt_enc_chat = OPENSSL_malloc(ENC_OVERHEAD + enc_msg_len);
    if (!pkt_enc_chat)
    {
        ossl_print_error("OPENSSL_malloc");
        goto cleanup;
    }
    p = pkt_enc_chat;

    // [1  enc_version]
    *p++ = 1;
    // [1  suite]
    *p++ = 1;
    // [2  reserved]
    *p++ = 0;
    *p++ = 0;
    // [8  room_epoch]
    put_u64_be(p, room->epoch);
    p += 8;
    // [8  seq]
    put_u64_be(p, room->send_seq);
    p += 8;
    // [16 nonce]
    memcpy(p, nonce, ENC_NONCE);
    p += ENC_NONCE;
    // [N  ciphertext]
    memcpy(p, enc_msg, enc_msg_len);
    p += enc_msg_len;
    // [16 tag]
    if (tag_len != ENC_TAG)
    {
        fprintf(stderr, "WRONG tag_len\n");
        goto cleanup;
    }
    memcpy(p, tag, tag_len);
    p += tag_len;

    if ((uint16_t)(p - pkt_enc_chat) != ENC_OVERHEAD + enc_msg_len)
    {
        fprintf(stderr, "WRONG pkt_enc_chat len");
        goto cleanup;
    }

    size_t pkt_enc_chat_len = ENC_OVERHEAD + enc_msg_len;

    if (enqueue_packet(c, &h, pkt_enc_chat, pkt_enc_chat_len) < 0)
    {
        fprintf(stderr, "enqueue_packet failed\n");
        goto cleanup;
    }
    if (set_epollout_to_client(epfd, c) < 0)
    {
        fprintf(stderr, "set_epollout_to_client failed\n");
        goto cleanup;
    }
    room->send_seq++;
    ret = 0;
cleanup:
    OPENSSL_free(enc_msg);
    OPENSSL_free(tag);
    OPENSSL_free(nonce);
    OPENSSL_free(pkt_enc_chat);
    return ret;
}

// PKT_ENC_CHAT
// [1  enc_version]
// [1  suite]
// [2  reserved]
// [8  room_epoch]
// [8  seq]
// [16 nonce]
// [N  ciphertext]
// [16 tag]
int client_recv_pkt_enc_chat(Client* c, Header* h, RoomSession* room, uint8_t* msg,
                             uint16_t msg_len, uint8_t** out_msg, uint16_t* out_msg_len)
{
    if (!c || !h || !room || !msg || !out_msg || msg_len < ENC_OVERHEAD || msg_len > PAYLOAD_SIZE)
    {
        return -1;
    }
    int      ret         = -1;
    uint8_t* p           = NULL;
    size_t   off         = 0;
    p                    = msg;
    uint8_t  enc_version = 0;
    uint8_t  suite       = 0;
    uint64_t room_epoch  = 0;
    uint64_t seq         = 0;
    uint8_t  nonce[ENC_NONCE];
    memset(nonce, 0, ENC_NONCE);
    uint8_t* ciphertext     = NULL;
    uint16_t ciphertext_len = msg_len - ENC_OVERHEAD;
    uint8_t* tag            = NULL;
    uint16_t tag_len        = ENC_TAG;
    *out_msg                = NULL;
    *out_msg_len            = 0;

    // [1  enc_version]
    enc_version = *(p + off);
    if (enc_version != 1)
    {
        goto cleanup;
    }
    off += 1;

    // [1  suite]
    suite = *(p + off);
    if (suite != 1)
    {
        goto cleanup;
    }
    off += 1;
    // [2  reserved]
    off += 2;

    // [8  room_epoch]
    room_epoch = get_u64_be(p + off);
    off += 8;

    if (room_epoch != room->epoch)
    {
        fprintf(stderr, "room_epoch mismatch\n");
        goto cleanup;
    }

    // [8  seq]
    seq = get_u64_be(p + off);
    off += 8;

    // [16 nonce]
    memcpy(nonce, p + off, ENC_NONCE);
    off += ENC_NONCE;

    // [N  ciphertext]
    ciphertext = p + off;
    off += ciphertext_len;

    // [16 tag]
    tag = p + off;
    off += tag_len;

    if (off != msg_len)
    {
        fprintf(stderr, "msg_len mismatch\n");
        goto cleanup;
    }

    if (decrypt_chat_message(nonce, room->room_key, h->sender_id, h->room_id, room_epoch, seq,
                             ciphertext, ciphertext_len, tag, out_msg, out_msg_len) < 0)
    {
        fprintf(stderr, "decrypt_chat_message failed\n");
        goto cleanup;
    }

    if (check_recv_seq(room, h->sender_id, seq) < 0)
    {
        fprintf(stderr, "replay detected\n");
        goto cleanup;
    }

    ret = 0;
cleanup:
    if (ret != 0)
    {
        OPENSSL_free(*out_msg);
        *out_msg     = NULL;
        *out_msg_len = 0;
    }
    return ret;
}

int client_response_challenge(int epfd, Client* c, uint8_t* msg, uint16_t msg_len,
                              EVP_PKEY* private_key)
{
    if (!msg || !private_key)
    {
        return -1;
    }
    int      ret     = -1;
    uint8_t* out     = NULL;
    size_t   out_len = 0;
    if (get_sign_challenge(c->id, c->name, msg, msg_len, private_key, &out, &out_len) < 0)
    {
        fprintf(stderr, "get_sign_challenge failed\n");
        goto cleanup;
    }
    Header h     = {0};
    h.flags      = 0;
    h.message_id = 0;
    h.room_id    = 0;
    h.sender_id  = c->id;
    h.timestamp  = (uint64_t)time(NULL);
    h.type       = PKT_AUTH_RESPONSE;
    h.version    = 1;

    if (enqueue_packet(c, &h, out, out_len) < 0)
    {
        fprintf(stderr, "enqueue_packet failed\n");
        goto cleanup;
    }
    if (set_epollout_to_client(epfd, c) < 0)
    {
        fprintf(stderr, "set_epollout_to_client failed\n");
        goto cleanup;
    }
    ret = 0;
cleanup:
    OPENSSL_free(out);
    return ret;
}
