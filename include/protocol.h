#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#define MAX_NAME_LEN 32
#define MAX_PAYLOAD_SIZE 1024
#define PAYLOAD_SIZE MAX_PAYLOAD_SIZE
#define BUF_SIZE 8192

#define FRAME_LEN_SIZE 4
#define VERSION_SIZE 1
#define TYPE_SIZE 1
#define FLAGS_SIZE 2
#define SENDER_ID_SIZE 4
#define ROOM_ID_SIZE 4
#define TIMESTAMP_SIZE 8
#define MESSAGE_ID_SIZE 4

#define HEADER_SIZE                                                                                \
    (VERSION_SIZE + TYPE_SIZE + FLAGS_SIZE + SENDER_ID_SIZE + ROOM_ID_SIZE + TIMESTAMP_SIZE +      \
     MESSAGE_ID_SIZE)

#define PAYLOAD_ID_AND_NAME_SIZE (SENDER_ID_SIZE + MAX_NAME_LEN)
#define PAYLOAD_REGISTER_OK_SIZE (SENDER_ID_SIZE + ROOM_ID_SIZE + MAX_NAME_LEN)

// AAD
// [1  packet_type]
// [4  sender_id]
// [4  to_client_id]#define ROOM_PASS_KEY_LEN  32

// [4 room_id]
// [8  epoch]
#define PACKET_TYPE_LEN 1
#define SENDER_ID_LEN 4
#define TO_CLIENT_ID_LEN 4
#define ROOM_ID_LEN 4
#define EPOCH_LEN 8
#define AAD_LEN (PACKET_TYPE_LEN + SENDER_ID_LEN + TO_CLIENT_ID_LEN + ROOM_ID_LEN + EPOCH_LEN)

// [4 frame_len]
// [1 version]
// [1 type]
// [2 flags]
// [4 sender_id]
// [4 room_id]
// [8 timestamp]
// [4 msg_id]
// [payload]
typedef struct Header
{
    uint8_t  version;
    uint8_t  type;
    uint16_t flags;
    uint32_t sender_id;
    uint32_t room_id;
    uint64_t timestamp;
    uint32_t message_id;
} Header;

typedef enum
{
    PKT_CHAT        = 0,
    PKT_REGISTER    = 1,
    PKT_REGISTER_OK = 2,

    PKT_ROOM_CREATE          = 3,
    PKT_ROOM_CREATE_PASSWORD = 4,

    // client -> server [4 room_id]
    PKT_ROOM_JOIN_BEGIN = 5,

    // server -> client [4 room_id][16 salt][32 nonce]
    PKT_ROOM_JOIN_CHALLENGE = 6,

    // client -> server [4 room_id][32 proof]
    PKT_ROOM_JOIN_PROOF = 7,

    // server -> client PKT_ROOM_CHANGE_OK/PKT_ERR
    PKT_ROOM_CHANGE_OK = 8,

    PKT_LEAVE = 9,
    PKT_NAME  = 10,
    PKT_ERR   = 11,

    PKT_AUTH_CHALLENGE = 12,
    PKT_AUTH_RESPONSE  = 13,
    PKT_AUTH_OK        = 14,
    PKT_ENC_KEY_BUNDLE = 15,

    // симметричный ключ комнаты.
    // все сообщения комнаты шифруются этим ключом
    PKT_ENC_ROOM_KEY = 16,

    // зашифрованные сообщения
    PKT_ENC_CHAT = 17,

    // после отправки списка пользователей
    // и чужих key bundles сервер должен отправлять
    PKT_ROOM_SYNC_DONE = 18,

    // PKT_REGISTER_BEGIN
    // клиент отправляет только имя
    // [name bytes]
    PKT_REGISTER_BEGIN = 19,

    // PKT_REGISTER_CHALLENGE
    // сервер отправляет
    // [4 temp_client_id]
    // [32 nonce]
    PKT_REGISTER_CHALLENGE = 20,

    // PKT_REGISTER_COMMIT
    // Клиент отправляет:
    // [2 identity_pub_der_len]
    // [identity_pub_der]
    // [2 signature_len]
    // [signature]
    // подписывается контекст
    // "chat_register_v1" || temp_client_id || username || nonce || identity_pub_der
    PKT_REGISTER_COMMIT = 21,
    PKT_ROOM_CHANGE,
    PKT_JOIN
} PacketType;

typedef enum
{
    PKT_OK               = 0,
    PKT_BAD_VERSION      = 1,
    PKT_BAD_TYPE         = 2,
    PKT_BAD_FLAGS        = 3,
    PKT_BAD_SENDER_ID    = 4,
    PKT_BAD_ROOM_ID      = 5,
    PKT_BAD_TIMESTAMP    = 6,
    PKT_BAD_MESSAGE_ID   = 7,
    PKT_BAD_PAYLOAD_SIZE = 8
} PacketState;

#endif