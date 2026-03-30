
#include "net.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <time.h>
#include <unistd.h>

#define ntohll(x) htonll(x)

uint64_t htonll(uint64_t x)
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
size_t my_strnlen(const char* s, size_t maxlen)
{
    size_t i;
    for (i = 0; i < maxlen && s[i] != '\0'; i++)
    {
    }
    return i;
}

// 0 успех
// -1 ошибка
int set_nonblocking(int server_fd)
{
    int flags = fcntl(server_fd, F_GETFL, 0);
    if (flags < 0)
    {
        perror("fcntl");
        return -1;
    }
    if (fcntl(server_fd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        perror("fcntl");
        return -1;
    }
    return 0;
}

void remove_client(int epfd, int cur_fd, Client* clients[], int* clients_count)
{

    for (int i = 0; i < *clients_count; i++)
    {
        if (clients[i] && clients[i]->ei.fd == cur_fd)
        {
            Client* temp                = clients[i];
            clients[i]                  = clients[*clients_count - 1];
            clients[*clients_count - 1] = NULL;
            (*clients_count)--;

            printf("[DISCONNECT] Client #%d\n", temp->id);

            if (epoll_ctl(epfd, EPOLL_CTL_DEL, cur_fd, NULL) < 0)
            {
                perror("epoll_ctl DEL");
            }
            close(cur_fd);
            free(temp);
            break;
        }
    }
}

void reject_packet(int epfd, Client* c, int cur_fd, Client* clients[], int* clients_count,
                   const char* reason, uint32_t message_id)
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
    if (h->type != PKT_NAME)
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
    if (h->room_id != 0)
    {
        return PKT_BAD_ROOM_ID;
    }
    if (msg_len == 0 || msg_len > PAYLOAD_SIZE)
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
        default:
            return "UNKNOWN_PACKET_STATE";
    }
}

int add_new_client(int epfd, int server_fd, Client* clients[], int* clients_count,
                   uint32_t* client_id)
{
    while (1)
    {
        if ((*clients_count) >= MAX_CLIENTS - 1)
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

        set_nonblocking(new_client_fd);

        Client* new_client = malloc(sizeof(Client));
        if (!new_client)
        {
            return -1;
        }
        memset(new_client, 0, sizeof(Client));
        new_client->id              = (*client_id)++;
        new_client->sa              = new_client_sa;
        new_client->ei.item         = CLIENT_ITEM;
        new_client->ei.fd           = new_client_fd;
        new_client->state           = STATE_WAIT_NAME;
        new_client->name[0]         = '\0';
        clients[(*clients_count)++] = new_client;

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
        printf("[CONNECT] Client #%d\n", new_client->id);
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

int is_name_taken(Client* clients[], int clients_count, const char* name)
{
    for (int i = 0; i < clients_count; i++)
    {
        if (clients[i] && clients[i]->state == STATE_READY && strcmp(clients[i]->name, name) == 0)
            return 1;
    }
    return 0;
}

void broadcast_message(int epfd, Client* c, Header* h, Client* clients[], int* clients_count,
                       char msg[], int len)
{

    for (int i = 0; i < *clients_count; i++)
    {
        if (clients[i]->ei.fd != c->ei.fd)
        {
            if (enqueue_packet(clients[i], h, msg, len) < 0)
            {
                continue;
            }
            if (set_epollout_to_client(epfd, clients[i]) < 0)
            {
                perror("set_epollout_to_client");
                remove_client(epfd, clients[i]->ei.fd, clients, clients_count);
                continue;
            }
        }
    }
}

int send_server_user_event(Client* c, uint32_t message_id, PacketType type, const char* name,
                           uint32_t user_id)
{
    if (type != PKT_JOIN && type != PKT_LEAVE)
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
    h.message_id = message_id;
    h.room_id    = 0;
    h.sender_id  = SERVER_ID;
    h.timestamp  = (uint64_t)time(NULL);
    h.type       = type;
    h.version    = 1;

    size_t name_len = strlen(name);
    char   msg[PAYLOAD_ID_AND_NAME_SIZE];

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

void broadcast_user_event(int epfd, Client* skip, Client* clients[], int clients_count,
                          PacketType type, uint32_t message_id)
{
    if (!skip)
    {
        return;
    }
    for (int i = 0; i < clients_count; i++)
    {
        if (!clients[i] || skip == clients[i])
        {
            continue;
        }
        if (send_server_user_event(clients[i], message_id, type, skip->name, skip->id) < 0)
        {
            continue;
        }
        set_epollout_to_client(epfd, clients[i]);
    }
}

int disconnect_client(int epfd, Client* c, Client* clients[], int* clients_count,
                      uint32_t message_id)
{
    if (!c || !clients)
    {
        return -1;
    }
    if (c->state == STATE_READY && c->name[0] != '\0')
    {
        broadcast_user_event(epfd, c, clients, *clients_count, PKT_LEAVE, message_id);
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
int enqueue_packet(Client* c, Header* header, const char* msg, uint32_t len)
{
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
    memcpy(c->conn.out_buf + c->conn.out_len, msg, len);
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
// dst должен быть размером хотя бы PAYLOAD_SIZE + 1
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
int try_pop_packet(Client* c, Header* header, char* dst, uint32_t* dst_len)
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

void send_server_error(int epfd, Client* c, const char msg[], uint32_t message_id)
{
    Header h;
    memset(&h, 0, sizeof(h));
    h.version    = 1;
    h.flags      = 0;
    h.message_id = message_id;
    h.type       = PKT_ERR;
    h.room_id    = 0;
    h.sender_id  = 0;
    h.timestamp  = (uint64_t)time(NULL);

    enqueue_packet(c, &h, msg, (uint32_t)strlen(msg));
    set_epollout_to_client(epfd, c);
}

// [ID 4][NAME 32]
int send_server_join(int epfd, Client* c, const char* name, uint32_t message_id)
{
    Header h;
    memset(&h, 0, sizeof(h));
    h.version    = 1;
    h.flags      = 0;
    h.message_id = message_id;
    h.type       = PKT_JOIN;
    h.room_id    = 0;
    h.sender_id  = SERVER_ID;
    h.timestamp  = (uint64_t)time(NULL);

    char msg[PAYLOAD_ID_AND_NAME_SIZE];
    memset(msg, 0, PAYLOAD_ID_AND_NAME_SIZE);

    size_t   off        = 0;
    uint32_t id_to_send = htonl(c->id);
    memcpy(msg + off, &id_to_send, sizeof(id_to_send));
    off += sizeof(id_to_send);

    size_t name_len = my_strnlen(name, MAX_NAME_LEN);
    memcpy(msg + off, name, name_len);

    if (enqueue_packet(c, &h, msg, PAYLOAD_ID_AND_NAME_SIZE) < 0)
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

// 0 успех
// -1 не влезло
int send_client_name(Client* c, const char name[])
{
    Header h;
    memset(&h, 0, sizeof(h));
    h.version    = 1;
    h.flags      = 0;
    h.message_id = 0;
    h.type       = PKT_NAME;
    h.room_id    = 0;
    h.sender_id  = SERVER_ID;
    h.timestamp  = (uint64_t)time(NULL);

    if (enqueue_packet(c, &h, name, strlen(name)) < 0)
    {
        return -1;
    };
    return 0;
}

int parse_client_id_and_name(char msg[], uint32_t msg_len, uint32_t* id, char name[])
{
    if (msg_len < SENDER_ID_SIZE)
    {
        return -1;
    }
    size_t off = 0;
    memcpy(id, msg + off, SENDER_ID_SIZE);
    *(id) = ntohl(*id);
    off += SENDER_ID_SIZE;

    size_t name_len = msg_len - off;
    if (name_len > MAX_NAME_LEN)
    {
        name_len = MAX_NAME_LEN;
    }
    memcpy(name, msg + off, name_len);
    name[name_len] = '\0';
    return 0;
}

// send_server_info(...)

// send_server_leave(...)

// create_server_socket
// accept_client
// connect_to_server