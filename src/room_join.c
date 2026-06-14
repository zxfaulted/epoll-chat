#include "room_join.h"
#include <string.h>
#include <time.h>

int client_send_pkt_room_join_begin(int epfd, Client* c, uint32_t room_id,
                                    char password[MAX_PASSWORD_LEN])
{
    if (!c || !password)
    {
        return -1;
    }

    Header h;
    memset(&h, 0, sizeof(h));
    h.flags      = 0;
    h.message_id = 0;
    h.room_id    = c->room_id;
    h.sender_id  = c->id;
    h.timestamp  = (uint64_t)time(NULL);
    h.type       = PKT_ROOM_JOIN_BEGIN;
    h.version    = 1;

    uint8_t  msg     = room_id;
    uint32_t msg_len = ROOM_ID_LEN;

    if (enqueue_packet(c, &h, &msg, msg_len) < 0)
    {
        return -1;
    }
    if (set_epollout_to_client(epfd, c) < 0)
    {
        return -1;
    }

    return 0;
}