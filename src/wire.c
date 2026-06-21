
#include "wire.h"
#include "types.h"

void put_u16_be(uint8_t* p, uint16_t v)
{
    p[0] = (uint8_t)((v >> 8) & 0xFF);
    p[1] = (uint8_t)(v & 0xFF);
}

uint16_t get_u16_be(const uint8_t* p)
{
    return (uint16_t)p[0] << 8 | (uint16_t)p[1];
}

void put_u32_be(uint8_t* p, uint32_t v)
{
    p[0] = (uint8_t)((v >> 24) & 0xFF);
    p[1] = (uint8_t)((v >> 16) & 0xFF);
    p[2] = (uint8_t)((v >> 8) & 0xFF);
    p[3] = (uint8_t)(v & 0xFF);
}

uint32_t get_u32_be(const uint8_t* p)
{
    return ((uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | (uint32_t)p[3]);
}

void put_u64_be(uint8_t* p, uint64_t v)
{
    p[0] = (uint8_t)((v >> 56) & 0xFF);
    p[1] = (uint8_t)((v >> 48) & 0xFF);
    p[2] = (uint8_t)((v >> 40) & 0xFF);
    p[3] = (uint8_t)((v >> 32) & 0xFF);
    p[4] = (uint8_t)((v >> 24) & 0xFF);
    p[5] = (uint8_t)((v >> 16) & 0xFF);
    p[6] = (uint8_t)((v >> 8) & 0xFF);
    p[7] = (uint8_t)(v & 0xFF);
}

uint64_t get_u64_be(const uint8_t* p)
{
    return ((uint64_t)p[0] << 56 | (uint64_t)p[1] << 48 | (uint64_t)p[2] << 40 |
            (uint64_t)p[3] << 32 | (uint64_t)p[4] << 24 | (uint64_t)p[5] << 16 |
            (uint64_t)p[6] << 8 | (uint64_t)p[7]);
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
        case PKT_REGISTER_BEGIN:
            return "PKT_REGISTER_BEGIN";
        case PKT_REGISTER_CHALLENGE:
            return "PKT_REGISTER_CHALLENGE";
        case PKT_REGISTER_RESPONSE:
            return "PKT_REGISTER_RESPONSE";
        case PKT_REGISTER_OK:
            return "PKT_REGISTER_OK";

        case PKT_AUTH_BEGIN:
            return "PKT_AUTH_BEGIN";
        case PKT_AUTH_CHALLENGE:
            return "PKT_AUTH_CHALLENGE";
        case PKT_AUTH_RESPONSE:
            return "PKT_AUTH_RESPONSE";
        case PKT_AUTH_OK:
            return "PKT_AUTH_OK";

        case PKT_ENC_KEY_BUNDLE:
            return "PKT_ENC_KEY_BUNDLE";

        case PKT_ROOM_CREATE:
            return "PKT_ROOM_CREATE";
        case PKT_ROOM_CREATE_PASSWORD:
            return "PKT_ROOM_CREATE_PASSWORD";
        case PKT_ROOM_CREATE_OK:
            return "PKT_ROOM_CREATE_OK";

        case PKT_ROOM_JOIN_BEGIN:
            return "PKT_ROOM_JOIN_BEGIN";
        case PKT_ROOM_PASSWORD_INFO:
            return "PKT_ROOM_PASSWORD_INFO";
        case PKT_ROOM_UNLOCK:
            return "PKT_ROOM_UNLOCK";
        case PKT_ROOM_CHANGE_OK:
            return "PKT_ROOM_CHANGE_OK";
        case PKT_ROOM_SYNC_DONE:
            return "PKT_ROOM_SYNC_DONE";

        case PKT_JOIN:
            return "PKT_JOIN";
        case PKT_LEAVE:
            return "PKT_LEAVE";

        case PKT_ENC_ROOM_KEY:
            return "PKT_ENC_ROOM_KEY";
        case PKT_ENC_CHAT:
            return "PKT_ENC_CHAT";

        default:
            return "PKT_UNKNOWN";
    }
}