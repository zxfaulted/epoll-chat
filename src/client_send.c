#include "room_crypto.h"
#include "room_join.h"
#include "room_password.h"
#include "wire.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

int client_send_pkt_room_join_begin(int epfd, Client* c, uint32_t room_id)
{
    if (!c)
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

    uint8_t msg[ROOM_ID_LEN];
    put_u32_be(msg, room_id);
    uint32_t msg_len = ROOM_ID_LEN;

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

int client_send_pkt_room_create(int epfd, Client* c, uint32_t room_id)
{
    Header h;
    h.flags      = 0;
    h.message_id = 0;
    h.room_id    = c->room_id;
    h.sender_id  = c->id;
    h.timestamp  = (uint64_t)time(NULL);
    h.type       = PKT_ROOM_CREATE;
    h.version    = 1;
    uint8_t msg[ROOM_ID_LEN];
    put_u32_be(msg, room_id);
    if (enqueue_packet(c, &h, msg, ROOM_ID_LEN) < 0)
    {
        return -1;
    }
    if (set_epollout_to_client(epfd, c) < 0)
    {
        return -1;
    }
    return 0;
}

// PKT_ROOM_CREATE_PASSWORD создает комнату и отправляет метаданные серверу
// client -> server:
// PKT_ROOM_CREATE_PASSWORD
// [4 room_id]
// [16 salt]  random
// [32 nonce] random
// password_key = PBKDF2(password, salt)
// [32 encrypted_room_key] encrypt(password_key, room_key)
// [16 tag] tag = auth_tag(
//     key        = password_key,
//     nonce      = nonce,
//     plaintext  = room_key,
//     aad        = "room_password_v1" || room_id
// )
// [32 verifier]
int client_send_pkt_room_create_password(int epfd, Client* c, uint32_t room_id,
                                         char    password[MAX_PASSWORD_LEN],
                                         uint8_t plaintext_room_key[ROOM_KEY_LEN])
{
    Header h;
    h.flags      = 0;
    h.message_id = 0;
    h.room_id    = c->room_id;
    h.sender_id  = c->id;
    h.timestamp  = (uint64_t)time(NULL);
    h.type       = PKT_ROOM_CREATE_PASSWORD;
    h.version    = 1;

    RoomPasswordInfo rpi;

    uint8_t msg[PKT_ROOM_CREATE_PASSWORD_PAYLOAD_LEN];
    if (build_pkt_room_create_password_payload(room_id, (uint8_t*)password, strlen(password), &rpi,
                                               plaintext_room_key, &msg) < 0)
    {
        return -1;
    }

    if (enqueue_packet(c, &h, msg, PKT_ROOM_CREATE_PASSWORD_PAYLOAD_LEN) < 0)
    {
        return -1;
    }
    if (set_epollout_to_client(epfd, c) < 0)
    {
        return -1;
    }
    return 0;
}

// [4 room_id]
// [8 epoch]
// [32 verifier]
int client_send_pkt_room_unlock(int epfd, Client* c, uint32_t room_id, uint64_t epoch,
                                uint8_t verifier[ROOM_PASSWORD_VERIFIER_LEN])
{
    if (!c)
    {
        return -1;
    }

    Header h;
    memset(&h, 0, sizeof(h));
    h.flags      = 0;
    h.message_id = 0;
    h.room_id    = room_id;
    h.sender_id  = c->id;
    h.timestamp  = (uint64_t)time(NULL);
    h.type       = PKT_ROOM_UNLOCK;
    h.version    = 1;

    size_t  off = 0;
    uint8_t msg[PKT_ROOM_UNLOCK_PAYLOAD_LEN];
    put_u32_be(msg, room_id);
    off += ROOM_ID_LEN;

    put_u64_be(msg + off, epoch);
    off += EPOCH_LEN;

    memcpy(msg + off, verifier, ROOM_PASSWORD_VERIFIER_LEN);
    off += ROOM_PASSWORD_VERIFIER_LEN;

    if (off != PKT_ROOM_UNLOCK_PAYLOAD_LEN)
    {
        return -1;
    }

    if (enqueue_packet(c, &h, msg, sizeof(msg)) < 0)
    {
        return -1;
    }
    if (set_epollout_to_client(epfd, c) < 0)
    {
        return -1;
    }

    return 0;
}

int client_send_password_room_rekey(int epfd, Client* c, RoomPasswordInfo* rpi)
{
    uint8_t msg[PKT_ROOM_PASSWORD_REKEY_PAYLOAD_LEN];
    memset(msg, 0, sizeof(msg));

    if (build_pkt_room_password_rekey_payload(c->room_id, rpi, &msg) < 0)
    {
        fprintf(stderr, "build_pkt_room_password_rekey_payload failed\n");
        return -1;
    }
    Header h;
    memset(&h, 0, sizeof(h));
    h.flags      = 0;
    h.message_id = 0;
    h.room_id    = c->room_id;
    h.sender_id  = c->id;
    h.timestamp  = (uint64_t)time(NULL);
    h.type       = PKT_ROOM_PASSWORD_REKEY;
    h.version    = 1;

    if (enqueue_packet(c, &h, msg, PKT_ROOM_PASSWORD_REKEY_PAYLOAD_LEN) < 0)
    {
        return -1;
    }
    if (set_epollout_to_client(epfd, c) < 0)
    {
        return -1;
    }
    return 0;
}
