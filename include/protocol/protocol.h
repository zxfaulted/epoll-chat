#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#define MAX_ROOMS 128
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
// [4  to_client_id]
// [4 room_id]
// [8  epoch]
#define PACKET_TYPE_LEN 1
#define SENDER_ID_LEN 4
#define TO_CLIENT_ID_LEN 4
#define ROOM_ID_LEN 4
#define EPOCH_LEN 8
#define ROOM_PASSWORD_VERIFIER_LEN 32
#define AAD_LEN (PACKET_TYPE_LEN + SENDER_ID_LEN + TO_CLIENT_ID_LEN + ROOM_ID_LEN + EPOCH_LEN)
#define PKT_ROOM_CREATE_PASSWORD_PAYLOAD_LEN                                                       \
    (ROOM_ID_LEN + EPOCH_LEN + ROOM_SALT_LEN + ROOM_NONCE_LEN + ENCRYPTED_ROOM_KEY_LEN +           \
     ROOM_TAG_LEN + ROOM_PASSWORD_VERIFIER_LEN)
#define PKT_ROOM_PASSWORD_REKEY_PAYLOAD_LEN PKT_ROOM_CREATE_PASSWORD_PAYLOAD_LEN

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

    PKT_ROOM_CREATE = 3,

    // PKT_ROOM_CREATE_PASSWORD создает комнату и отправляет метаданные серверу
    // client -> server:
    // PKT_ROOM_CREATE_PASSWORD
    // [4 room_id]
    // [16 salt]  random
    // [32 nonce] random
    // password_key = KBKDF(password, salt) с HMAC и md_gost12_256
    // [32 encrypted_room_key] encrypt(password_key, room_key)
    // [16 tag] tag = auth_tag(
    //     key        = password_key,
    //     nonce      = nonce,
    //     plaintext  = room_key,
    //     aad        = "room_password_v1" || room_id
    // )
    PKT_ROOM_CREATE_PASSWORD = 4,

    // PKT_ROOM_JOIN_BEGIN "хочу войти в эту комнату"
    // только в состояниях ROOM_NONE / ROOM_READY
    // client -> server [4 room_id]
    PKT_ROOM_JOIN_BEGIN = 5,

    // PKT_ROOM_PASSWORD_INFO передает клиенту данные для проверки пароля
    // server -> client
    // [4  room_id]
    // [8 epoch]
    // [16 salt]
    // [32 nonce]
    // [16 tag]
    // [32 encrypted_room_key]
    // client:
    // password_key = KDF(password, salt)
    // room_key = AEAD_Decrypt(password_key,
    //                         encrypted_room_key,
    //                         nonce,
    //                         tag)

    PKT_ROOM_PASSWORD_INFO = 6,

    // client -> server
    // клиент сообщает: я смог расшифровать room_key
    PKT_ROOM_UNLOCK = 7,

    // server -> client PKT_ROOM_CHANGE_OK
    PKT_ROOM_CHANGE_OK = 8,

    // Смена ключа:
    // 1. Лидер генерирует новый ключ комнаты
    // old_room_key = room->room_key
    // new_room_key = random(32)
    // new_epoch = room->epoch + 1
    // save_room_session(rooms, count, room_id, new_epoch, new_room_key);

    // 2. Лидер обновляет данные на сервере
    // PKT_ROOM_PASSWORD_REKEY клиент отправляет метаданные серверу
    // о новом ключе под тем же паролем
    // client -> server:
    // salt = same salt
    // password_key = KDF(password, salt)
    // new_nonce = random(32)
    // encrypted_room_key = AEAD_Encrypt(password_key, new_room_key)
    // payload:
    // [4  room_id]
    // [8  epoch]
    // [16 salt]
    // [32 nonce]
    // [16 tag]
    // [32 encrypted_room_key]
    PKT_ROOM_PASSWORD_REKEY = 9,

    PKT_LEAVE = 10,
    PKT_NAME  = 11,
    PKT_ERR   = 12,

    PKT_AUTH_BEGIN     = 13,
    PKT_AUTH_CHALLENGE = 14,
    PKT_AUTH_RESPONSE  = 15,
    PKT_AUTH_OK        = 16,
    PKT_ENC_KEY_BUNDLE = 17,

    // симметричный ключ комнаты.
    // все сообщения комнаты шифруются этим ключом
    PKT_ENC_ROOM_KEY = 18,

    // зашифрованные сообщения
    PKT_ENC_CHAT = 19,

    // после отправки списка пользователей
    // и чужих key bundles сервер должен отправлять
    PKT_ROOM_SYNC_DONE = 20,

    // PKT_REGISTER_BEGIN
    // клиент отправляет только имя
    // [name bytes]
    PKT_REGISTER_BEGIN = 21,

    // PKT_REGISTER_CHALLENGE
    // сервер отправляет
    // [4 temp_client_id]
    // [32 nonce]
    PKT_REGISTER_CHALLENGE = 22,

    // PKT_REGISTER_RESPONSE
    // Клиент отправляет:
    // [2 identity_pub_der_len]
    // [identity_pub_der]
    // [2 signature_len]
    // [signature]
    // подписывается контекст
    // "chat_register_v1" || temp_client_id || username || nonce || identity_pub_der
    PKT_REGISTER_RESPONSE = 23,
    PKT_ROOM_CHANGE,
    PKT_JOIN,
    PKT_ROOM_CREATE_OK
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
    PKT_BAD_PAYLOAD_SIZE = 8,
    PKT_BAD_EPOCH        = 9,
    PKT_BAD_SALT         = 10,
    PKT_BAD_VERIFIER     = 11,
    PKT_BAD_NONCE        = 12,
    PKT_BAD_TAG          = 13,
    PKT_BAD_ROOM_KEY     = 14
} PacketState;

#endif