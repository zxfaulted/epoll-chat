#include "client_recv.h"

int client_recv_pkt_room_password_info(uint8_t* msg, uint16_t msg_len, uint32_t* out_room_id,
                                       RoomPasswordInfo* out_rpi)
{
    if (parse_pkt_room_password_info(msg, msg_len, out_room_id, out_rpi) < 0)
    {
        return -1;
    }
    return 0;
}