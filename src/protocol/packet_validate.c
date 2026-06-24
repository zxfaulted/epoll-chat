#include "protocol/packet_validate.h"

PacketState validate_packet_begin(uint32_t msg_len, Header* h)
{
    if (h->version != 1)
    {
        return PKT_BAD_VERSION;
    }
    if (h->type != PKT_AUTH_BEGIN && h->type != PKT_REGISTER_BEGIN)
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