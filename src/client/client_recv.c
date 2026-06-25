#include "client/client_recv.h"

#include "e2e/e2e_message.h"
#include "protocol/wire.h"

#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>

int client_recv_pkt_room_password_info(uint8_t* msg, uint16_t msg_len, uint32_t* out_room_id,
                                       RoomPasswordInfo* out_rpi)
{
    if (parse_pkt_room_password_info(msg, msg_len, out_room_id, out_rpi) < 0)
    {
        return -1;
    }
    return 0;
}

// PKT_ENC_CHAT
// [1  enc_version]
// [1  suite]
// [2  reserved]
// [8  room_epoch]
// [8  seq]
// [16 nonce]
// [N  ciphertext]
// [16 tag]
int client_recv_pkt_enc_chat(Client* c, Header* h, RoomSession* room, uint8_t* msg,
                             uint16_t msg_len, uint8_t** out_msg, uint16_t* out_msg_len)
{
    if (!c || !h || !room || !msg || !out_msg || msg_len < ENC_OVERHEAD || msg_len > PAYLOAD_SIZE)
    {
        return -1;
    }
    int      ret         = -1;
    uint8_t* p           = NULL;
    size_t   off         = 0;
    p                    = msg;
    uint8_t  enc_version = 0;
    uint8_t  suite       = 0;
    uint64_t room_epoch  = 0;
    uint64_t seq         = 0;
    uint8_t  nonce[ENC_NONCE];
    memset(nonce, 0, ENC_NONCE);
    uint8_t* ciphertext     = NULL;
    uint16_t ciphertext_len = msg_len - ENC_OVERHEAD;
    uint8_t* tag            = NULL;
    uint16_t tag_len        = ENC_TAG;
    *out_msg                = NULL;
    *out_msg_len            = 0;

    // [1  enc_version]
    enc_version = *(p + off);
    if (enc_version != 1)
    {
        goto cleanup;
    }
    off += 1;

    // [1  suite]
    suite = *(p + off);
    if (suite != 1)
    {
        goto cleanup;
    }
    off += 1;
    // [2  reserved]
    off += 2;

    // [8  room_epoch]
    room_epoch = get_u64_be(p + off);
    off += 8;

    if (room_epoch != room->epoch)
    {
        fprintf(stderr, "room_epoch mismatch\n");
        goto cleanup;
    }

    // [8  seq]
    seq = get_u64_be(p + off);
    off += 8;

    // [16 nonce]
    memcpy(nonce, p + off, ENC_NONCE);
    off += ENC_NONCE;

    // [N  ciphertext]
    ciphertext = p + off;
    off += ciphertext_len;

    // [16 tag]
    tag = p + off;
    off += tag_len;

    if (off != msg_len)
    {
        fprintf(stderr, "msg_len mismatch\n");
        goto cleanup;
    }

    if (decrypt_chat_message(nonce, room->room_key, h->sender_id, h->room_id, room_epoch, seq,
                             ciphertext, ciphertext_len, tag, out_msg, out_msg_len) < 0)
    {
        fprintf(stderr, "decrypt_chat_message failed\n");
        goto cleanup;
    }

    if (check_recv_seq(room, h->sender_id, seq) < 0)
    {
        fprintf(stderr, "replay detected\n");
        goto cleanup;
    }

    ret = 0;
cleanup:
    if (ret != 0)
    {
        OPENSSL_free(*out_msg);
        *out_msg     = NULL;
        *out_msg_len = 0;
    }
    return ret;
}
