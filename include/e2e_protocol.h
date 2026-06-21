#ifndef E2E_PROTOCOL_H
#define E2E_PROTOCOL_H

#include "protocol.h"

#define MIN_PASSWORD_LEN 4
#define MAX_PASSWORD_LEN 128

#define ROOM_SALT_LEN 16
#define ROOM_NONCE_LEN 32
#define ROOM_PASS_KEY_LEN 32
#define MAX_CLIENTS 1024
#define ROOM_KEY_LEN 32
#define ROOM_TAG_LEN 16
#define ENCRYPTED_ROOM_KEY_LEN ROOM_KEY_LEN
#define PASSWORD_KEY_LEN 32

// PKT_ENC_CHAT
// [1  enc_version]
// [1  suite]
// [2  reserved]
// [8  room_epoch]
// [8  seq]
// [16 nonce]
// [N  ciphertext]
// [16 tag]
#define ENC_VERSION 1
#define ENC_SUITE 1
#define ENC_RESERVED 2
#define ENC_ROOM_EPOCH 8
#define ENC_SEQ 8
#define ENC_NONCE 16
#define ENC_TAG 16
#define ENC_HEADER (ENC_VERSION + ENC_SUITE + ENC_RESERVED + ENC_ROOM_EPOCH + ENC_SEQ + ENC_NONCE)
#define ENC_OVERHEAD (ENC_HEADER + ENC_TAG)
#define ENC_PLAINTEXT_MAX_LEN (PAYLOAD_SIZE - ENC_OVERHEAD)

// [1 packet_type]
// [1 enc_version]
// [1 suite]
// [2 reserved]
// [4 sender_id]
// [4 room_id]
// [8 room_epoch]
// [8 seq]
#define AAD_FOR_ENC_CHAT_LEN                                                                       \
    (PACKET_TYPE_LEN + ENC_VERSION + ENC_SUITE + ENC_RESERVED + SENDER_ID_LEN + ROOM_ID_LEN +      \
     ENC_ROOM_EPOCH + ENC_SEQ)

// [4 to_client_id]
// [8 Fepoch]
// [16 nonce]
// [16 tag]
// [32 encrypted_room_key]
#define PKT_ENC_ROOM_KEY_NONCE_LEN 32
#define PKT_ENC_ROOM_KEY_TAG_LEN 16
#define PKT_ENC_ROOM_KEY_CIPHERTEXT_LEN ROOM_KEY_LEN
#define PKT_ENC_ROOM_KEY_PAYLOAD_LEN                                                               \
    (4 + 8 + PKT_ENC_ROOM_KEY_NONCE_LEN + PKT_ENC_ROOM_KEY_TAG_LEN +                               \
     PKT_ENC_ROOM_KEY_CIPHERTEXT_LEN)
#define WRAPPING_KEY_LEN 32

#endif