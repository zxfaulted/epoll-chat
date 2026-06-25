#include "protocol/packet_parse.h"

#include "protocol/pkt_build.h"
#include "protocol/protocol.h"
#include "protocol/wire.h"

#include <arpa/inet.h>
#include <string.h>

int packet_parse_auth_register_ok(const uint8_t* msg, uint32_t msg_len, uint32_t* out_client_id,
                                  uint32_t* out_room_id, char name[])
{
    int ret = -1;
    if (!msg || !out_client_id || !out_room_id || !name)
    {
        return -1;
    }
    if (msg_len < SENDER_ID_SIZE)
    {
        return -1;
    }
    const uint8_t* p   = msg;
    const uint8_t* end = msg + msg_len;

    NEED(p, end, SENDER_ID_SIZE);
    *out_client_id = get_u32_be(p);
    p += SENDER_ID_SIZE;

    NEED(p, end, ROOM_ID_SIZE);
    *out_room_id = get_u32_be(p);
    p += ROOM_ID_SIZE;

    size_t name_len = end - p;
    NEED(p, end, name_len);
    if (name_len > MAX_NAME_LEN)
    {
        return -1;
    }
    memcpy(name, p, name_len);
    name[name_len] = '\0';
    ret            = 0;
cleanup:
    return ret;
}

int packet_parse_client_id_name(const uint8_t* msg, uint32_t msg_len, uint32_t* out_client_id,
                                char name[])
{
    int ret = -1;
    if (!msg || !out_client_id || !name)
    {
        return -1;
    }
    if (msg_len < SENDER_ID_SIZE)
    {
        return -1;
    }
    const uint8_t* p   = msg;
    const uint8_t* end = msg + msg_len;

    NEED(p, end, SENDER_ID_SIZE);
    *out_client_id = get_u32_be(p);
    p += SENDER_ID_SIZE;

    size_t name_len = end - p;
    NEED(p, end, name_len);
    if (name_len > MAX_NAME_LEN)
    {
        return -1;
    }
    memcpy(name, p, name_len);
    name[name_len] = '\0';
    ret            = 0;
cleanup:
    return ret;
}