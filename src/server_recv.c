#include "server_recv.h"
#include "pkt_build.h"
#include "protocol.h"
#include "room_password.h"
#include "wire.h"
#include <stdint.h>

int server_recv_pkt_room_join_begin(uint8_t* msg, uint16_t msg_len, uint32_t* out_room_id)
{
    if (!msg || !out_room_id)
    {
        return -1;
    }
    if (msg_len != ROOM_ID_LEN)
    {
        return -1;
    }
    uint32_t room_id = get_u32_be(msg);
    if (room_id < 1 || room_id > MAX_ROOMS)
    {
        return -1;
    }
    *out_room_id = room_id;
    return 0;
}

int server_recv_pkt_room_unlock(uint8_t* msg, uint16_t msg_len, uint32_t* out_room_id)
{
    if (!msg || !out_room_id)
    {
        return -1;
    }
    if (msg_len != ROOM_ID_LEN)
    {
        return -1;
    }
    uint32_t room_id = get_u32_be(msg);
    if (room_id < 1 || room_id > MAX_ROOMS)
    {
        return -1;
    }
    *out_room_id = room_id;
    return 0;
}
