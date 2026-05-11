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

// [4 to_client_id]
// [8 Fepoch]
// [16 nonce]
// [16 tag]
// [32 encrypted_room_key]
#define PKT_ENC_ROOM_KEY_NONCE_LEN 16
#define PKT_ENC_ROOM_KEY_TAG_LEN 16
#define PKT_ENC_ROOM_KEY_CIPHERTEXT_LEN ROOM_KEY_LEN
#define PKT_ENC_ROOM_KEY_PAYLOAD_LEN                                                               \
    (4 + 8 + PKT_ENC_ROOM_KEY_NONCE_LEN + PKT_ENC_ROOM_KEY_TAG_LEN +                               \
     PKT_ENC_ROOM_KEY_CIPHERTEXT_LEN)
#define ROOM_KEY_LEN 32
#define WRAPPING_KEY_LEN 32

#define MAX_PENDING_REGISTRATIONS 128
#define REGISTRATION_TTL_SECONDS 60
#define CHALLENGE_LEN 32

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
    PKT_CHAT           = 0,
    PKT_REGISTER       = 1,
    PKT_REGISTER_OK    = 2,
    PKT_JOIN           = 3,
    PKT_LEAVE          = 4,
    PKT_NAME           = 5,
    PKT_ERR            = 6,
    PKT_ROOM_CHANGE    = 7,
    PKT_ROOM_CHANGE_OK = 8,

    PKT_AUTH_CHALLENGE = 9,

    PKT_AUTH_RESPONSE = 10,

    PKT_AUTH_OK = 11,

    PKT_ENC_KEY_BUNDLE = 12,

    // симметричный ключ комнаты.
    //  все сообщения комнаты шифруются этим ключом
    PKT_ENC_ROOM_KEY = 13,

    // зашифрованные сообщения
    PKT_ENC_CHAT = 14,

    // после отправки списка пользователей
    // и чужих key bundles сервер должен отправлять
    PKT_ROOM_SYNC_DONE = 15,

    // PKT_REGISTER_BEGIN
    // клиент отправляет только имя
    // [name bytes]
    PKT_REGISTER_BEGIN = 16,

    // PKT_REGISTER_CHALLENGE
    // сервер отправляет
    // [4 temp_client_id]
    // [32 nonce]
    PKT_REGISTER_CHALLENGE = 17,

    // PKT_REGISTER_COMMIT
    // Клиент отправляет:
    // [2 identity_pub_der_len]
    // [identity_pub_der]
    // [2 signature_len]
    // [signature]
    // подписывается контекст
    // "chat_register_v1" || temp_client_id || username || nonce || identity_pub_der
    PKT_REGISTER_COMMIT = 18
} PacketType;

#endif