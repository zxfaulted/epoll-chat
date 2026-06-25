#include "server/server_send.h"

#include "e2e/e2e_protocol.h"
#include "protocol/message_id.h"
#include "protocol/wire.h"
#include "server/server_clients.h"
#include "transport/epoll_io.h"
#include "transport/packet_io.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

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

int server_send_room_password_info(int epfd, Client* c, uint32_t room_id, RoomPasswordInfo* rpi,
                                   uint32_t* message_id)
{
    uint8_t  buf[PKT_ROOM_PASSWORD_INFO_LEN];
    uint16_t buf_len = 0;
    if (build_pkt_room_password_info(room_id, rpi->epoch, rpi, buf, &buf_len) < 0)
    {
        fprintf(stderr, "build_pkt_room_password_info failed\n");
        return -1;
    }
    Header h;
    h.flags      = 0;
    h.room_id    = room_id;
    h.message_id = next_message_id(message_id);
    h.timestamp  = (uint64_t)time(NULL);
    h.type       = PKT_ROOM_PASSWORD_INFO;
    h.sender_id  = SERVER_ID;
    h.version    = 1;

    if (enqueue_packet(c, &h, buf, buf_len) < 0)
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

int server_send_pkt_room_create_ok(int epfd, Client* c, uint32_t room_id, uint32_t* message_id)
{
    Header h;
    h.flags      = 0;
    h.message_id = next_message_id(message_id);
    h.room_id    = room_id;
    h.sender_id  = SERVER_ID;
    h.timestamp  = (uint64_t)time(NULL);
    h.type       = PKT_ROOM_CREATE_OK;
    h.version    = 1;
    uint8_t  msg[ROOM_ID_LEN];
    uint32_t msg_len = ROOM_ID_LEN;
    put_u32_be(msg, room_id);

    if (enqueue_packet(c, &h, msg, msg_len) < 0)
    {
        return -1;
    }
    if (set_epollout_to_client(epfd, c) < 0)
    {
        return -1;
    }
    return 0;
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

int send_server_auth_ok(Client* c, uint32_t room_id, const char* name, uint32_t user_id,
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
    h.type       = PKT_AUTH_OK;
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