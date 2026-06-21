#include "room_join.h"
#include "room.h"
#include "wire.h"
#include <string.h>
#include <time.h>

int build_pkt_join_begin_payload(uint8_t* out_msg, uint16_t* out_msg_len, uint32_t room_id)
{
    if (!out_msg || !out_msg_len)
    {
        return -1;
    }

    put_u32_be(out_msg, room_id);
    *out_msg_len = ROOM_ID_LEN;

    return 0;
}

int parse_pkt_join_begin_payload(uint8_t* msg, uint16_t msg_len, uint32_t* out_room_id)
{
    if (!msg || !out_room_id)
    {
        return -1;
    }
    if (msg_len != ROOM_ID_LEN)
    {
        return -1;
    }
    *out_room_id = get_u32_be(msg);
    return 0;
}

int validate_room_join(RoomSession* rooms, uint32_t room_id)
{
    if (!find_room_session(rooms, MAX_ROOMS, room_id))
    {
        return -1;
    }
    else
    {
        return 0;
    }
}
