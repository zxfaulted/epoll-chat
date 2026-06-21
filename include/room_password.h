#ifndef ROOM_PASSWORD_H
#define ROOM_PASSWORD_H

#include "e2e_protocol.h"

#include <stdint.h>

#define PKT_ROOM_PASSWORD_INFO_LEN                                                                 \
    (ROOM_ID_LEN + EPOCH_LEN + ROOM_SALT_LEN + ROOM_NONCE_LEN + ENCRYPTED_ROOM_KEY_LEN +           \
     ROOM_TAG_LEN)

typedef struct RoomPasswordInfo
{
    uint64_t epoch;

    uint8_t encrypted_room_key[ENCRYPTED_ROOM_KEY_LEN];
    uint8_t salt[ROOM_SALT_LEN];
    uint8_t nonce[ROOM_NONCE_LEN];
    uint8_t tag[ROOM_TAG_LEN];
} RoomPasswordInfo;

int build_pkt_room_password_info(uint32_t room_id, uint64_t epoch, RoomPasswordInfo* rpi,
                                 uint8_t* out_msg, uint16_t* out_msg_len);
int parse_pkt_room_password_info(uint8_t* msg, uint16_t msg_len, uint32_t* out_room_id,
                                 RoomPasswordInfo* out_room_password_info);
int parse_pkt_room_create_password(uint8_t* msg, uint16_t msg_len, uint32_t* out_room_id,
                                   RoomPasswordInfo* rpi);
int build_pkt_room_create_password_payload(
    uint32_t room_id, uint8_t* password, uint16_t password_len, RoomPasswordInfo* rpi,
    uint8_t plaintext_room_key[ROOM_KEY_LEN],
    uint8_t (*out_msg)[PKT_ROOM_CREATE_PASSWORD_PAYLOAD_LEN]);
int parse_pkt_room_password_rekey_payload(uint8_t* msg, uint16_t msg_len, uint32_t* out_room_id,
                                          RoomPasswordInfo* rpi);
int build_pkt_room_password_rekey_payload(uint32_t room_id, RoomPasswordInfo* rpi,
                                          uint8_t (*out_msg)[PKT_ROOM_CREATE_PASSWORD_PAYLOAD_LEN]);

#endif // ROOM_PASSWORD_H