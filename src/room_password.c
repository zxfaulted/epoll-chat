#include "room_password.h"
#include "pkt_build.h"
#include "room_crypto.h"
#include "server_room.h"
#include "wire.h"
#include <crypto_core.h>
#include <openssl/rand.h>
#include <room_crypto.h>
#include <stdio.h>
#include <string.h>

// [4  room_id]
// [8 epoch]
// [16 salt]
// [32 nonce]
// [32 encrypted_room_key]
// [16 tag]
int build_pkt_room_password_info(uint32_t room_id, uint64_t epoch, RoomPasswordInfo* rpi,
                                 uint8_t* out_msg, uint16_t* out_msg_len)
{
    if (!out_msg || !out_msg_len || !rpi)
    {
        return -1;
    }

    uint8_t payload[PKT_ROOM_PASSWORD_INFO_LEN];
    memset(payload, 0, PKT_ROOM_PASSWORD_INFO_LEN);
    size_t off = 0;

    put_u32_be(payload, room_id);
    off += ROOM_ID_LEN;

    put_u64_be(payload + off, epoch);
    off += EPOCH_LEN;

    memcpy(payload + off, rpi->salt, ROOM_SALT_LEN);
    off += ROOM_SALT_LEN;

    memcpy(payload + off, rpi->nonce, ROOM_NONCE_LEN);
    off += ROOM_NONCE_LEN;

    memcpy(payload + off, rpi->encrypted_room_key, ENCRYPTED_ROOM_KEY_LEN);
    off += ENCRYPTED_ROOM_KEY_LEN;

    memcpy(payload + off, rpi->tag, ROOM_TAG_LEN);
    off += ROOM_TAG_LEN;

    if (off != PKT_ROOM_PASSWORD_INFO_LEN)
    {
        fprintf(stderr, "off and default pkt_size differ\n");
        return -1;
    }

    memcpy(out_msg, payload, off);
    *out_msg_len = off;
    return 0;
}

// [4  room_id]
// [8 epoch]
// [16 salt]
// [32 nonce]
// [32 encrypted_room_key]
// [16 tag]
int parse_pkt_room_password_info(uint8_t* msg, uint16_t msg_len, uint32_t* out_room_id,
                                 RoomPasswordInfo* out_room_password_info)
{
    uint8_t* p   = msg;
    uint8_t* end = msg + msg_len;

    NEED(p, end, ROOM_ID_LEN);
    *out_room_id = get_u32_be(p);
    p += ROOM_ID_LEN;

    NEED(p, end, EPOCH_LEN);
    out_room_password_info->epoch = get_u64_be(p);
    p += EPOCH_LEN;

    NEED(p, end, ROOM_SALT_LEN);
    memcpy(out_room_password_info->salt, p, ROOM_SALT_LEN);
    p += ROOM_SALT_LEN;

    NEED(p, end, ROOM_NONCE_LEN);
    memcpy(out_room_password_info->nonce, p, ROOM_NONCE_LEN);
    p += ROOM_NONCE_LEN;

    NEED(p, end, ENCRYPTED_ROOM_KEY_LEN);
    memcpy(out_room_password_info->encrypted_room_key, p, ENCRYPTED_ROOM_KEY_LEN);
    p += ENCRYPTED_ROOM_KEY_LEN;

    NEED(p, end, ROOM_TAG_LEN);
    memcpy(out_room_password_info->tag, p, ROOM_TAG_LEN);
    p += ROOM_TAG_LEN;

    if (p != end)
    {
        goto cleanup;
    }

    return 0;
cleanup:
    return -1;
}

// PKT_ROOM_CREATE_PASSWORD создает комнату и отправляет метаданные серверу
// client -> server:
// PKT_ROOM_CREATE_PASSWORD
// [4 room_id]
// [8 epoch]
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
int build_pkt_room_create_password_payload(uint32_t room_id, uint8_t* password,
                                           uint16_t password_len, RoomPasswordInfo* rpi,
                                           uint8_t plaintext_room_key[ROOM_KEY_LEN],
                                           uint8_t (*out_msg)[PKT_ROOM_CREATE_PASSWORD_PAYLOAD_LEN])
{
    if (!password || !rpi || !out_msg || !*out_msg)
    {
        return -1;
    }
    uint8_t buf[PKT_ROOM_CREATE_PASSWORD_PAYLOAD_LEN];
    memset(buf, 0, sizeof(buf));
    size_t off = 0;

    rpi->epoch = 1;

    put_u32_be(buf + off, room_id);
    off += ROOM_ID_LEN;

    put_u64_be(buf + off, rpi->epoch);
    off += EPOCH_LEN;

    uint8_t salt[ROOM_SALT_LEN];
    memset(salt, 0, ROOM_SALT_LEN);
    if (RAND_bytes(salt, ROOM_SALT_LEN) != 1)
    {
        ossl_print_error("RAND_bytes");
        return -1;
    }
    memcpy(buf + off, salt, ROOM_SALT_LEN);
    off += ROOM_SALT_LEN;

    uint8_t nonce[ROOM_NONCE_LEN];
    memset(nonce, 0, ROOM_NONCE_LEN);
    if (RAND_bytes(nonce, ROOM_NONCE_LEN) != 1)
    {
        ossl_print_error("RAND_bytes");
        return -1;
    }
    memcpy(buf + off, nonce, ROOM_NONCE_LEN);
    off += ROOM_NONCE_LEN;

    memcpy(rpi->nonce, nonce, ROOM_NONCE_LEN);
    memcpy(rpi->salt, salt, ROOM_SALT_LEN);
    rpi->epoch = 1;
    if (encrypt_room_key_with_password(room_id, password, password_len, plaintext_room_key, rpi) <
        0)
    {
        return -1;
    }
    memcpy(buf + off, rpi->encrypted_room_key, ENCRYPTED_ROOM_KEY_LEN);
    off += ENCRYPTED_ROOM_KEY_LEN;
    memcpy(buf + off, rpi->tag, ROOM_TAG_LEN);
    off += ROOM_TAG_LEN;

    if (off != sizeof(buf))
    {
        return -1;
    }
    memcpy(*out_msg, buf, sizeof(buf));

    return 0;
}

// PKT_ROOM_PASSWORD_REKEY создает комнату и отправляет метаданные серверу
// client -> server:
// PKT_ROOM_CREATE_PASSWORD
// [4 room_id]
// [8 epoch]
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
int build_pkt_room_password_rekey_payload(uint32_t room_id, RoomPasswordInfo* rpi,
                                          uint8_t (*out_msg)[PKT_ROOM_CREATE_PASSWORD_PAYLOAD_LEN])
{
    if (!rpi || !out_msg || !*out_msg)
    {
        return -1;
    }
    uint8_t buf[PKT_ROOM_CREATE_PASSWORD_PAYLOAD_LEN];
    memset(buf, 0, sizeof(buf));
    size_t off = 0;

    put_u32_be(buf + off, room_id);
    off += ROOM_ID_LEN;

    put_u64_be(buf + off, rpi->epoch);
    off += EPOCH_LEN;

    memcpy(buf + off, rpi->salt, ROOM_SALT_LEN);
    off += ROOM_SALT_LEN;

    memcpy(buf + off, rpi->nonce, ROOM_NONCE_LEN);
    off += ROOM_NONCE_LEN;

    memcpy(buf + off, rpi->encrypted_room_key, ENCRYPTED_ROOM_KEY_LEN);
    off += ENCRYPTED_ROOM_KEY_LEN;
    memcpy(buf + off, rpi->tag, ROOM_TAG_LEN);
    off += ROOM_TAG_LEN;

    if (off != sizeof(buf))
    {
        return -1;
    }
    memcpy(*out_msg, buf, sizeof(buf));

    return 0;
}

// PKT_ROOM_CREATE_PASSWORD создает комнату и отправляет метаданные серверу
// client -> server:
// PKT_ROOM_CREATE_PASSWORD
// [4 room_id]
// [8 epoch]
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
int parse_pkt_room_password_rekey_payload(uint8_t* msg, uint16_t msg_len, uint32_t* out_room_id,
                                          RoomPasswordInfo* rpi)
{
    int      ret = -1;
    uint8_t* end = msg + msg_len;
    size_t   off = 0;

    NEED(msg + off, end, ROOM_ID_LEN);
    uint32_t room_id = get_u32_be(msg + off);
    off += ROOM_ID_LEN;

    NEED(msg + off, end, EPOCH_LEN);
    uint64_t epoch = get_u64_be(msg + off);
    off += EPOCH_LEN;
    rpi->epoch = epoch;

    NEED(msg + off, end, ROOM_SALT_LEN);
    memcpy(rpi->salt, msg + off, ROOM_SALT_LEN);
    off += ROOM_SALT_LEN;

    NEED(msg + off, end, ROOM_NONCE_LEN);
    memcpy(rpi->nonce, msg + off, ROOM_NONCE_LEN);
    off += ROOM_NONCE_LEN;

    NEED(msg + off, end, ENCRYPTED_ROOM_KEY_LEN);
    memcpy(rpi->encrypted_room_key, msg + off, ENCRYPTED_ROOM_KEY_LEN);
    off += ENCRYPTED_ROOM_KEY_LEN;

    NEED(msg + off, end, ROOM_TAG_LEN);
    memcpy(rpi->tag, msg + off, ROOM_TAG_LEN);
    off += ROOM_TAG_LEN;

    if (msg + off != end)
    {
        fprintf(stderr, "parse_pkt_room_create_password: off and msg_len differ\n");
        goto cleanup;
    }

    *out_room_id = room_id;

    ret = 0;
cleanup:
    return ret;
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
int parse_pkt_room_create_password(uint8_t* msg, uint16_t msg_len, uint32_t* out_room_id,
                                   RoomPasswordInfo* rpi)
{
    int      ret = -1;
    uint8_t* end = msg + msg_len;
    size_t   off = 0;

    NEED(msg + off, end, ROOM_ID_LEN);
    uint32_t room_id = get_u32_be(msg + off);
    off += ROOM_ID_LEN;

    NEED(msg + off, end, EPOCH_LEN);
    uint64_t epoch = get_u64_be(msg + off);
    off += EPOCH_LEN;
    rpi->epoch = epoch;

    NEED(msg + off, end, ROOM_SALT_LEN);
    memcpy(rpi->salt, msg + off, ROOM_SALT_LEN);
    off += ROOM_SALT_LEN;

    NEED(msg + off, end, ROOM_NONCE_LEN);
    memcpy(rpi->nonce, msg + off, ROOM_NONCE_LEN);
    off += ROOM_NONCE_LEN;

    NEED(msg + off, end, ENCRYPTED_ROOM_KEY_LEN);
    memcpy(rpi->encrypted_room_key, msg + off, ENCRYPTED_ROOM_KEY_LEN);
    off += ENCRYPTED_ROOM_KEY_LEN;

    NEED(msg + off, end, ROOM_TAG_LEN);
    memcpy(rpi->tag, msg + off, ROOM_TAG_LEN);
    off += ROOM_TAG_LEN;

    if (msg + off != end)
    {
        fprintf(stderr, "parse_pkt_room_create_password: off and msg_len differ\n");
        goto cleanup;
    }

    *out_room_id = room_id;

    ret = 0;
cleanup:
    return ret;
}
