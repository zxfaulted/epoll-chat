
#include "net.h"
#include "crypto.h"
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

#define ntohll(x) htonll(x)

static uint64_t htonll(uint64_t x)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint32_t low    = htonl((uint32_t)(x & 0xFFFFFFFFULL));
    uint32_t high   = htonl((uint32_t)(x >> 32));
    uint64_t result = ((uint64_t)low << 32) | high;
    return result;
#else
    return x;
#endif
}

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

const char* packet_state_str(PacketState st)
{
    switch (st)
    {
        case PKT_OK:
            return "PKT_OK";
        case PKT_BAD_VERSION:
            return "PKT_BAD_VERSION";
        case PKT_BAD_FLAGS:
            return "PKT_BAD_FLAGS";
        case PKT_BAD_SENDER_ID:
            return "PKT_BAD_SENDER_ID";
        case PKT_BAD_ROOM_ID:
            return "PKT_BAD_ROOM_ID";
        case PKT_BAD_TIMESTAMP:
            return "PKT_BAD_TIMESTAMP";
        case PKT_BAD_MESSAGE_ID:
            return "PKT_BAD_MESSAGE_ID";
        case PKT_BAD_PAYLOAD_SIZE:
            return "PKT_BAD_PAYLOAD_SIZE";
        case PKT_BAD_TYPE:
            return "PKT_BAD_TYPE";
        default:
            return "UNKNOWN_PACKET_STATE";
    }
}

const char* packet_type_str(PacketType type)
{
    switch (type)
    {
        case PKT_NAME:
            return "PKT_NAME";
        case PKT_CHAT:
            return "PKT_CHAT";
        case PKT_JOIN:
            return "PKT_JOIN";
        case PKT_LEAVE:
            return "PKT_LEAVE";
        case PKT_ERR:
            return "PKT_ERR";
        case PKT_REGISTER_OK:
            return "PKT_REGISTER_OK";
        case PKT_ROOM_CHANGE:
            return "PKT_ROOM_CHANGE";
        case PKT_ROOM_CHANGE_OK:
            return "PKT_ROOM_CHANGE_OK";
        case PKT_ENC_KEY_BUNDLE:
            return "PKT_ENC_KEY_BUNDLE";
        case PKT_ENC_ROOM_KEY:
            return "PKT_ENC_ROOM_KEY";
        case PKT_ENC_CHAT:
            return "PKT_ENC_CHAT";
        case PKT_REGISTER_BEGIN:
            return "PKT_REGISTER_BEGIN";
        case PKT_REGISTER_CHALLENGE:
            return "PKT_REGISTER_CHALLENGE";
        case PKT_REGISTER_COMMIT:
            return "PKT_REGISTER_COMMIT";
        case PKT_AUTH_CHALLENGE:
            return "PKT_AUTH_CHALLENGE";
        case PKT_AUTH_RESPONSE:
            return "PKT_AUTH_RESPONSE";
        default:
            return "PKT_UNKNOWN";
    }
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

// кладет пакет сообщения msg и длины len в out_buf
// возвращает:
// 0 успех
// -1 не влезло
// [4 frame_len]
// [1 version]
// [1 type]
// [2 flags]
// [4 sender_id]
// [4 room_id]
// [8 timestamp]
// [4 msg_id]
// [payload]
int enqueue_packet(Client* c, Header* header, const uint8_t* msg, uint32_t len)
{
    if (!c || !header || (!msg && len > 0) || len > PAYLOAD_SIZE)
    {
        return -1;
    }
    // если пакет не влезает, делается смещение неотправленного в начало
    // -4 как проверка от переполнения
    uint32_t packet_size = FRAME_LEN_SIZE + HEADER_SIZE + len;
    if (packet_size > BUF_SIZE - c->conn.out_len)
    {
        if (c->conn.out_sent > 0)
        {
            memmove(c->conn.out_buf, c->conn.out_buf + c->conn.out_sent,
                    c->conn.out_len - c->conn.out_sent);
            c->conn.out_len -= c->conn.out_sent;
            c->conn.out_sent = 0;
        }
    }
    // если не влезло даже после смещения влево, ошибка
    if (packet_size > BUF_SIZE - c->conn.out_len)
    {
        return -1;
    }
    // [4 frame_len]
    uint32_t frame_len = htonl(HEADER_SIZE + len);
    memcpy(c->conn.out_buf + c->conn.out_len, &frame_len, FRAME_LEN_SIZE);
    c->conn.out_len += FRAME_LEN_SIZE;

    //[1 version]
    uint8_t hv = header->version;

    memcpy(c->conn.out_buf + c->conn.out_len, &hv, VERSION_SIZE);
    c->conn.out_len += VERSION_SIZE;

    //[1 type]
    uint8_t type = header->type;
    memcpy(c->conn.out_buf + c->conn.out_len, &type, TYPE_SIZE);
    c->conn.out_len += TYPE_SIZE;

    // [2 flags]
    // -1 не влезло
    // [4 frame_len]
    uint16_t flags = htons(header->flags);
    memcpy(c->conn.out_buf + c->conn.out_len, &flags, FLAGS_SIZE);
    c->conn.out_len += FLAGS_SIZE;

    // [4 sender_id]
    uint32_t sender_id = htonl(header->sender_id);
    memcpy(c->conn.out_buf + c->conn.out_len, &sender_id, SENDER_ID_SIZE);
    c->conn.out_len += SENDER_ID_SIZE;

    // [4 room_id]
    uint32_t room_id = htonl(header->room_id);
    memcpy(c->conn.out_buf + c->conn.out_len, &room_id, ROOM_ID_SIZE);
    c->conn.out_len += ROOM_ID_SIZE;

    // [8 timestamp]
    uint64_t timestamp = htonll(header->timestamp);
    memcpy(c->conn.out_buf + c->conn.out_len, &timestamp, TIMESTAMP_SIZE);
    c->conn.out_len += TIMESTAMP_SIZE;

    // [4 msg_id]
    uint32_t msg_id = htonl(header->message_id);
    memcpy(c->conn.out_buf + c->conn.out_len, &msg_id, MESSAGE_ID_SIZE);
    c->conn.out_len += MESSAGE_ID_SIZE;

    // [payload]
    if (len > 0)
    {
        if (!msg)
        {
            return -1;
        }
        memcpy(c->conn.out_buf + c->conn.out_len, msg, len);
    }
    c->conn.out_len += len;
    return 0;
}

// recv в in_buf
// возвращает
// bytes > 0 при успехе
// 0 пока нет данных
// -1 соединение закрыто
// -2 ошибка
int recv_into_inbuf(Client* c)
{
    if (c->conn.in_len > BUF_SIZE)
    {
        return -2;
    }

    if (c->conn.in_len == BUF_SIZE)
    {
        // места больше нет, а try_pop_packet ничего не смог съесть
        return -2;
    }
    ssize_t bytes = recv(c->ei.fd, c->conn.in_buf + c->conn.in_len, BUF_SIZE - c->conn.in_len, 0);
    if (bytes == 0)
    {
        return -1;
    }
    if (bytes < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            return 0;
        }
        else
        {
            return -2;
        }
    }
    c->conn.in_len += bytes;
    return bytes;
}

// pop пакета из in_buf в dst и dst_len
// dst должен быть размером PAYLOAD_SIZE
// 1 при успешном извлечении
// 0 в буфере нет полного ответа
// -2 ошибка протокола

// [4 frame_len]
// [1 version]
// [1 type]
// [2 flags]
// [4 sender_id]
// [4 room_id]
// [8 timestamp]
// [4 msg_id]
// [payload]
int try_pop_packet(Client* c, Header* header, uint8_t* dst, uint32_t* dst_len)
{
    size_t off = 0;
    // [4 frame_len]
    uint32_t len;
    if (c->conn.in_len < FRAME_LEN_SIZE)
    {
        return 0;
    }
    memcpy(&len, c->conn.in_buf, FRAME_LEN_SIZE);
    off += FRAME_LEN_SIZE;
    len = ntohl(len);
    if (len > HEADER_SIZE + PAYLOAD_SIZE || len == 0 || len < HEADER_SIZE)
    {
        return -2;
    }
    if (c->conn.in_len < FRAME_LEN_SIZE + len)
    {
        return 0;
    }
    // [1 version]
    memcpy(&header->version, c->conn.in_buf + off, VERSION_SIZE);
    off += VERSION_SIZE;
    // [1 type]
    memcpy(&header->type, c->conn.in_buf + off, TYPE_SIZE);
    off += TYPE_SIZE;
    // [2 flags]
    memcpy(&header->flags, c->conn.in_buf + off, FLAGS_SIZE);
    off += FLAGS_SIZE;
    // [4 sender_id]
    memcpy(&header->sender_id, c->conn.in_buf + off, SENDER_ID_SIZE);
    off += SENDER_ID_SIZE;
    // [4 room_id]
    memcpy(&header->room_id, c->conn.in_buf + off, ROOM_ID_SIZE);
    off += ROOM_ID_SIZE;
    // [8 timestamp]
    memcpy(&header->timestamp, c->conn.in_buf + off, TIMESTAMP_SIZE);
    off += TIMESTAMP_SIZE;
    // [4 msg_id]
    memcpy(&header->message_id, c->conn.in_buf + off, MESSAGE_ID_SIZE);
    off += MESSAGE_ID_SIZE;
    // [payload]
    // -1 не влезло
    // [4 frame_len]
    size_t payload_len = len - HEADER_SIZE;
    if (payload_len > PAYLOAD_SIZE)
    {
        return -2;
    }
    memcpy(dst, c->conn.in_buf + off, payload_len);
    *dst_len = payload_len;

    size_t packet_size = FRAME_LEN_SIZE + len;
    if (packet_size > c->conn.in_len)
    {
        return 0;
    }
    memmove(c->conn.in_buf, c->conn.in_buf + packet_size, c->conn.in_len - packet_size);
    c->conn.in_len -= (packet_size);

    header->flags      = ntohs(header->flags);
    header->sender_id  = ntohl(header->sender_id);
    header->room_id    = ntohl(header->room_id);
    header->timestamp  = ntohll(header->timestamp);
    header->message_id = ntohl(header->message_id);
    return 1;
}

// возвращает
// 0 при успешной отправке или неготовности сокета
// -1 при ошибке
int flush_send(Client* c)
{
    while (c->conn.out_sent < c->conn.out_len)
    {
        ssize_t bytes = send(c->ei.fd, c->conn.out_buf + c->conn.out_sent,
                             c->conn.out_len - c->conn.out_sent, 0);
        if (bytes < 0)
        {
            // сокет не готов
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                return 0;
            }
            // ошибка
            else
            {
                perror("send");
                return -1;
            }
        }
        else if (bytes == 0)
        {
            return -1;
        }
        else
        {
            c->conn.out_sent += bytes;
        }
    }
    if (c->conn.out_sent == c->conn.out_len)
    {
        c->conn.out_sent = 0;
        c->conn.out_len  = 0;
    }
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

// 0 успех
// -1 ошибка
int add_user_entry(UserEntry* ue, const char* name, uint32_t id)
{
    if (!ue || !name)
    {
        return -1;
    }
    int empty_slot = -1;
    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (ue[i].used == 1)
        {
            if (ue[i].id == id)
            {
                return -1;
            }
            continue;
        }
        if (empty_slot == -1)
        {
            empty_slot = i;
        }
    }
    if (empty_slot != -1)
    {
        ue[empty_slot].id = id;
        strncpy(ue[empty_slot].name, name, sizeof(ue[empty_slot].name) - 1);
        ue[empty_slot].name[sizeof(ue[empty_slot].name) - 1] = '\0';
        ue[empty_slot].used                                  = 1;
        return 0;
    }
    return -1;
}

int remove_user_entry_by_id(UserEntry* ue, uint32_t id)
{
    if (!ue)
    {
        return -1;
    }
    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (ue[i].used == 0 || ue[i].id != id)
        {
            continue;
        }
        ue[i].id = 0;
        memset(ue[i].name, 0, sizeof(ue[i].name));
        ue[i].used = 0;
        return 0;
    }
    return -1;
}

const char* find_user_name_by_id(const UserEntry* ue, uint32_t id)
{
    if (!ue)
    {
        return NULL;
    }
    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (ue[i].used == 0 || ue[i].id != id)
        {
            continue;
        }
        return ue[i].name;
    }
    return NULL;
}

int send_kb(Client* c, uint8_t* kb, uint16_t kb_len, uint32_t owner_id, uint32_t room_id,
            uint32_t* message_id)
{
    Header h     = {0};
    h.type       = PKT_ENC_KEY_BUNDLE;
    h.sender_id  = owner_id;
    h.room_id    = room_id;
    h.message_id = message_id ? next_message_id(message_id) : 0;
    h.timestamp  = (uint64_t)time(NULL);
    h.version    = 1;
    h.flags      = 0;

    if (enqueue_packet(c, &h, kb, kb_len) < 0)
    {
        fprintf(stderr, "enqueue_packet failed\n");
        return -1;
    }
    return 0;
}

int send_server_ready_key_bundles(int epfd, Client* c, Client* clients[], int* clients_count,
                                  uint32_t* message_id)
{
    if (!c || !clients)
    {
        return -1;
    }
    for (int i = 0; i < *clients_count; i++)
    {
        if (clients[i] && clients[i]->state == STATE_READY && c != clients[i] &&
            clients[i]->room_id == c->room_id && clients[i]->has_kb == 1)
        {
            if (send_kb(c, clients[i]->raw_kb, clients[i]->raw_kb_len, clients[i]->id,
                        clients[i]->room_id, message_id) < 0)
            {
                fprintf(stderr, "send_kb failed\n");
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

// рассылка key bundle вошедшего всем существующим в данной комнате
int send_server_new_key_bundle(int epfd, Client* c, Client* clients[], int clients_count,
                               uint32_t* message_id)
{

    if (!c || !clients)
    {
        return -1;
    }
    for (int i = 0; i < clients_count; i++)
    {
        if (clients[i] && clients[i]->state == STATE_READY && c != clients[i] &&
            clients[i]->room_id == c->room_id && clients[i]->has_kb == 1)
        {
            if (send_kb(clients[i], c->raw_kb, c->raw_kb_len, c->id, c->room_id, message_id) < 0)
            {
                fprintf(stderr, "send_kb failed\n");
                return -1;
            }
            if (set_epollout_to_client(epfd, clients[i]) < 0)
            {
                fprintf(stderr, "send_kb failed\n");
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

int forward_room_key_packet(int epfd, Client* clients[], int clients_count, Client* from, Header* h,
                            uint8_t* msg, uint32_t msg_len, uint32_t* message_id)
{
    if (!clients || !from || !h || !msg || !message_id)
    {
        return -1;
    }

    if (msg_len != PKT_ENC_ROOM_KEY_PAYLOAD_LEN)
    {
        send_server_error(epfd, from, "WRONG PAYLOAD LEN", message_id);
        return -1;
    }

    if (h->room_id != from->room_id)
    {
        send_server_error(epfd, from, "YOU ARE NOT IN THIS ROOM", message_id);
        return 0;
    }

    uint32_t to_client_id = get_u32_be(msg);

    if (to_client_id == from->id)
    {
        send_server_error(epfd, from, "YOU ARE NOT IN THIS ROOM", message_id);
        return 0;
    }

    Client* to = find_client(clients, clients_count, to_client_id);
    if (!to)
    {
        send_server_error(epfd, from, "NO CLIENT WITH THAT ID", message_id);
        return 0;
    }

    if (to->room_id != from->room_id)
    {
        send_server_error(epfd, from, "YOU ARE NOT IN DIFFERENT ROOMS", message_id);
        return 0;
    }

    Header h_out     = {0};
    h_out.flags      = 0;
    h_out.message_id = next_message_id(message_id);
    h_out.room_id    = from->room_id;
    h_out.sender_id  = from->id;
    h_out.timestamp  = (uint64_t)time(NULL);
    h_out.type       = PKT_ENC_ROOM_KEY;
    h_out.version    = 1;

    if (enqueue_packet(to, &h_out, msg, msg_len) < 0)
    {
        return -1;
    }

    if (set_epollout_to_client(epfd, to) < 0)
    {
        return -1;
    }
    return 0;
}

// [1  enc_version]
// [1  suite]
// [2  reserved]
// [8  room_epoch]
// [8  seq]
// [16 nonce]
// [N  ciphertext]
// [16 tag]
int check_recv_seq(RoomSession* room, uint64_t peer_id, uint64_t recv_seq)
{
    RoomPeerRecvState* slot = NULL;
    for (size_t i = 0; i < MAX_CLIENTS; i++)
    {
        if (room->recv[i].used && room->recv[i].peer_id == peer_id)
        {
            slot = &room->recv[i];
            break;
        }
    }
    if (!slot)
    {
        for (size_t i = 0; i < MAX_CLIENTS; i++)
        {
            if (!room->recv[i].used)
            {
                slot          = &room->recv[i];
                slot->peer_id = peer_id;
                slot->seq     = 0;
                slot->used    = 1;
                break;
            }
        }
    }
    if (!slot)
    {
        fprintf(stderr, "recv table is full\n");
        return -1;
    }

    if (slot->seq >= recv_seq)
    {
        fprintf(stderr, "replay detected for peer#%" PRIu64 "\n", peer_id);
        return -1;
    }
    slot->seq = recv_seq;
    return 0;
}

int add_pending_registration(PendingReg* pr, const char* name, uint8_t* challenge,
                             uint32_t client_id)
{
    int idx = find_in_pending_registrations(pr, name, client_id);
    if (idx >= 0)
    {
        if (pr[idx].expires_at > (uint64_t)time(NULL))
        {
            return -2;
        }
        else
        {
            pr[idx].used = 0;
        }
    }
    for (int i = 0; i < MAX_PENDING_REGISTRATIONS; i++)
    {
        if (!pr[i].used)
        {
            strncpy(pr[i].name, name, MAX_NAME_LEN + 1);
            if (challenge)
            {
                memcpy(pr[i].challenge, challenge, CHALLENGE_LEN);
            }
            pr[i].id         = client_id;
            pr[i].used       = 1;
            pr[i].expires_at = (uint64_t)time(NULL) + (uint64_t)60;
            return 0;
        }
    }
    return -1;
}

int find_in_pending_registrations(PendingReg* pr, const char* name, uint32_t client_id)
{
    for (int i = 0; i < MAX_PENDING_REGISTRATIONS; i++)
    {
        if (!pr[i].used)
        {
            continue;
        }
        if (strcmp(pr[i].name, name) != 0)
        {
            continue;
        }
        if (pr[i].expires_at <= (uint64_t)time(NULL))
        {
            pr[i].used = 0;
            continue;
        }
        if (pr[i].id != client_id)
        {
            continue;
        }
        return i;
    }
    return -1;
}

void remove_pending_registration(PendingReg* pr, const char* name, uint32_t client_id)
{
    for (int i = 0; i < MAX_PENDING_REGISTRATIONS; i++)
    {
        if (strcmp(pr[i].name, name) == 0 && pr[i].id == client_id)
        {
            pr[i].used = 0;
        }
    }
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

int server_send_registration_challenge(int epfd, Client* c, uint32_t client_id,
                                       const uint8_t challenge[CHALLENGE_LEN], uint32_t* message_id)
{
    if (!c || !message_id)
    {
        return -1;
    }
    uint8_t payload[4 + CHALLENGE_LEN];
    put_u32_be(payload, client_id);
    memcpy(payload + 4, challenge, CHALLENGE_LEN);

    Header h     = {0};
    h.version    = 1;
    h.type       = PKT_REGISTER_CHALLENGE;
    h.sender_id  = SERVER_ID;
    h.room_id    = 0;
    h.message_id = next_message_id(message_id);
    h.timestamp  = (uint64_t)time(NULL);

    if (enqueue_packet(c, &h, payload, sizeof(payload)) < 0)
    {
        fprintf(stderr, "enqueue_packet failed\n");
        return -1;
    }
    if (set_epollout_to_client(epfd, c) < 0)
    {
        fprintf(stderr, "set_epollout_to_client failed\n");
        return -1;
    }
    return 0;
}