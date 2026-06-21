#include "server_send.h"
#include "e2e_protocol.h"
#include "room_password.h"
#include "transport.h"
#include "wire.h"
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
    h.room_id    = 0;
    h.message_id = next_message_id(message_id);
    h.timestamp  = (uint64_t)time(NULL);
    h.type       = PKT_ROOM_PASSWORD_INFO;
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