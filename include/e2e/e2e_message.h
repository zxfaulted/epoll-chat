#ifndef E2E_MESSAGE_H
#define E2E_MESSAGE_H

#include "e2e/e2e_protocol.h"
#include <stdint.h>

// [4 frame_len]
// [24 Header]
// [32 EncChatHeader] входит в AAD
// [ciphertext] шифруется
// [tag]
// Кузнечик + MGM = AEAD
typedef struct
{
    // версия протокола
    uint8_t version;
    // алгоритм шифрования
    uint8_t suite;
    // резерв для выравнивания структуры
    uint16_t reserved;
    // версия ключа
    uint64_t room_epoch;
    // счетчик сообщения
    uint64_t seq;
    uint8_t  nonce[16];

} EncChatHeader;

int encrypt_chat_message(uint8_t room_key[ROOM_KEY_LEN], uint32_t sender_id, uint32_t room_id,
                         uint64_t epoch, uint64_t send_seq, uint8_t* msg, uint16_t msg_len,
                         uint8_t** out_msg, uint16_t* out_msg_len, uint8_t** out_tag,
                         uint16_t* out_tag_len, uint8_t** out_nonce);

int decrypt_chat_message(uint8_t* nonce, uint8_t room_key[ROOM_KEY_LEN], uint32_t sender_id,
                         uint32_t room_id, uint64_t epoch, uint64_t seq, uint8_t* msg,
                         uint16_t msg_len, uint8_t* tag, uint8_t** out_msg, uint16_t* out_msg_len);

int kuznechik_encrypt_message(uint8_t* nonce, uint8_t* enc_key, uint8_t* msg, int msg_len,
                              uint8_t* mac_key, uint8_t aad[AAD_FOR_ENC_CHAT_LEN], uint8_t** out,
                              uint16_t* out_len, uint8_t** tag_out, uint16_t* tag_out_len);

int kuznechik_decrypt_message(uint8_t* nonce, uint8_t* enc_key, uint8_t* msg, int msg_len,
                              uint8_t* mac_key, uint8_t aad[AAD_FOR_ENC_CHAT_LEN], uint8_t** out,
                              uint16_t* out_len, uint8_t* tag_in, uint16_t tag_in_len);

#endif // E2E_MESSAGE_H