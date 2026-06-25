#include "protocol/packet_validate.h"

#include <openssl/crypto.h>

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

PacketState validate_packet_room_password(uint32_t room_id, RoomPasswordInfo* rpi)
{
    if (rpi->epoch != 1)
    {
        return PKT_BAD_EPOCH;
    }
    if (room_id < 1 || room_id > MAX_ROOMS)
    {
        return PKT_BAD_ROOM_ID;
    }
    uint8_t zero_salt[ROOM_SALT_LEN] = {0};
    if (CRYPTO_memcmp(rpi->salt, zero_salt, ROOM_SALT_LEN) == 0)
    {
        return PKT_BAD_SALT;
    }
    uint8_t zero_verifier[ROOM_PASSWORD_VERIFIER_LEN] = {0};
    if (CRYPTO_memcmp(rpi->verifier, zero_verifier, ROOM_PASSWORD_VERIFIER_LEN) == 0)
    {
        return PKT_BAD_VERIFIER;
    }
    uint8_t zero_nonce[ROOM_NONCE_LEN] = {0};
    if (CRYPTO_memcmp(rpi->nonce, zero_nonce, ROOM_NONCE_LEN) == 0)
    {
        return PKT_BAD_NONCE;
    }

    uint8_t zero_tag[ROOM_TAG_LEN] = {0};
    if (CRYPTO_memcmp(rpi->tag, zero_tag, ROOM_TAG_LEN) == 0)
    {
        return PKT_BAD_TAG;
    }

    uint8_t zero_key[ENCRYPTED_ROOM_KEY_LEN] = {0};
    if (CRYPTO_memcmp(rpi->encrypted_room_key, zero_key, ENCRYPTED_ROOM_KEY_LEN) == 0)
    {
        return PKT_BAD_ROOM_KEY;
    }

    return PKT_OK;
}

PacketState validate_packet_room_password_rekey(uint32_t room_id, const ServerRoom* room,
                                                RoomPasswordInfo* rpi)
{
    if (!room || !rpi)
    {
        return PKT_BAD_PAYLOAD_SIZE;
    }

    if (room_id < 1 || room_id > MAX_ROOMS)
    {
        return PKT_BAD_ROOM_ID;
    }

    if (rpi->epoch != room->rpi.epoch + 1)
    {
        return PKT_BAD_EPOCH;
    }

    uint8_t zero_salt[ROOM_SALT_LEN]                  = {0};
    uint8_t zero_nonce[ROOM_NONCE_LEN]                = {0};
    uint8_t zero_tag[ROOM_TAG_LEN]                    = {0};
    uint8_t zero_key[ENCRYPTED_ROOM_KEY_LEN]          = {0};
    uint8_t zero_verifier[ROOM_PASSWORD_VERIFIER_LEN] = {0};

    if (CRYPTO_memcmp(rpi->salt, zero_salt, ROOM_SALT_LEN) == 0)
        return PKT_BAD_SALT;

    if (CRYPTO_memcmp(rpi->nonce, zero_nonce, ROOM_NONCE_LEN) == 0)
        return PKT_BAD_NONCE;

    if (CRYPTO_memcmp(rpi->tag, zero_tag, ROOM_TAG_LEN) == 0)
        return PKT_BAD_TAG;

    if (CRYPTO_memcmp(rpi->encrypted_room_key, zero_key, ENCRYPTED_ROOM_KEY_LEN) == 0)
        return PKT_BAD_ROOM_KEY;

    if (CRYPTO_memcmp(rpi->verifier, zero_verifier, ROOM_PASSWORD_VERIFIER_LEN) == 0)
        return PKT_BAD_VERIFIER;

    return PKT_OK;
}