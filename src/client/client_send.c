#include "client/client_send.h"

#include "auth/auth.h"
#include "crypto/crypto_core.h"
#include "e2e/e2e_message.h"
#include "e2e/room_crypto.h"
#include "e2e/room_join.h"
#include "e2e/room_key_wrap.h"
#include "protocol/wire.h"
#include "transport/epoll_io.h"
#include "transport/packet_io.h"

#include <openssl/crypto.h>
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

// PKT_ENC_CHAT
// [1  enc_version]
// [1  suite]
// [2  reserved]
// [8  room_epoch]
// [8  seq]
// [16 nonce]
// [N  ciphertext]
// [16 tag]
int client_send_encrypted_chat(int epfd, Client* c, RoomSession* room, uint8_t* msg,
                               uint16_t msg_len)
{
    if (!c || !room || !msg || msg_len > ENC_PLAINTEXT_MAX_LEN)
    {
        return -1;
    }
    int    ret            = -1;
    Header h              = {0};
    h.flags               = 0;
    h.message_id          = 0;
    h.room_id             = room->room_id;
    h.sender_id           = c->id;
    h.type                = PKT_ENC_CHAT;
    h.version             = 1;
    h.timestamp           = (uint64_t)time(NULL);
    uint8_t* enc_msg      = NULL;
    uint16_t enc_msg_len  = 0;
    uint8_t* tag          = NULL;
    uint16_t tag_len      = 0;
    uint8_t* pkt_enc_chat = NULL;
    uint8_t* p            = NULL;
    uint8_t* nonce        = NULL;

    if (encrypt_chat_message(room->room_key, c->id, c->room_id, room->epoch, room->send_seq, msg,
                             msg_len, &enc_msg, &enc_msg_len, &tag, &tag_len, &nonce) < 0)
    {
        fprintf(stderr, "encrypt_chat_message failed\n");
        goto cleanup;
    }
    if (enc_msg_len > ENC_PLAINTEXT_MAX_LEN)
    {
        fprintf(stderr, "enc_msg_len too large\n");
        goto cleanup;
    }
    pkt_enc_chat = OPENSSL_malloc(ENC_OVERHEAD + enc_msg_len);
    if (!pkt_enc_chat)
    {
        ossl_print_error("OPENSSL_malloc");
        goto cleanup;
    }
    p = pkt_enc_chat;

    // [1  enc_version]
    *p++ = 1;
    // [1  suite]
    *p++ = 1;
    // [2  reserved]
    *p++ = 0;
    *p++ = 0;
    // [8  room_epoch]
    put_u64_be(p, room->epoch);
    p += 8;
    // [8  seq]
    put_u64_be(p, room->send_seq);
    p += 8;
    // [16 nonce]
    memcpy(p, nonce, ENC_NONCE);
    p += ENC_NONCE;
    // [N  ciphertext]
    memcpy(p, enc_msg, enc_msg_len);
    p += enc_msg_len;
    // [16 tag]
    if (tag_len != ENC_TAG)
    {
        fprintf(stderr, "WRONG tag_len\n");
        goto cleanup;
    }
    memcpy(p, tag, tag_len);
    p += tag_len;

    if ((uint16_t)(p - pkt_enc_chat) != ENC_OVERHEAD + enc_msg_len)
    {
        fprintf(stderr, "WRONG pkt_enc_chat len");
        goto cleanup;
    }

    size_t pkt_enc_chat_len = ENC_OVERHEAD + enc_msg_len;

    if (enqueue_packet(c, &h, pkt_enc_chat, pkt_enc_chat_len) < 0)
    {
        fprintf(stderr, "enqueue_packet failed\n");
        goto cleanup;
    }
    if (set_epollout_to_client(epfd, c) < 0)
    {
        fprintf(stderr, "set_epollout_to_client failed\n");
        goto cleanup;
    }
    room->send_seq++;
    ret = 0;
cleanup:
    OPENSSL_free(enc_msg);
    OPENSSL_free(tag);
    OPENSSL_free(nonce);
    OPENSSL_free(pkt_enc_chat);
    return ret;
}

int client_send_challenge_response(int epfd, Client* c, uint8_t* msg, uint16_t msg_len,
                                   EVP_PKEY* private_key)
{
    if (!msg || !private_key)
    {
        return -1;
    }
    int      ret     = -1;
    uint8_t* out     = NULL;
    size_t   out_len = 0;
    if (get_sign_challenge(c->id, c->name, msg, msg_len, private_key, &out, &out_len) < 0)
    {
        fprintf(stderr, "get_sign_challenge failed\n");
        goto cleanup;
    }
    Header h     = {0};
    h.flags      = 0;
    h.message_id = 0;
    h.room_id    = 0;
    h.sender_id  = c->id;
    h.timestamp  = (uint64_t)time(NULL);
    h.type       = PKT_AUTH_RESPONSE;
    h.version    = 1;

    if (enqueue_packet(c, &h, out, out_len) < 0)
    {
        fprintf(stderr, "enqueue_packet failed\n");
        goto cleanup;
    }
    if (set_epollout_to_client(epfd, c) < 0)
    {
        fprintf(stderr, "set_epollout_to_client failed\n");
        goto cleanup;
    }
    ret = 0;
cleanup:
    OPENSSL_free(out);
    return ret;
}

// [4 to_client_id]
// [8 epoch]
// [16 nonce]
// [16 tag]
// [32 encrypted_room_key]
int send_room_key_to_peer(int epfd, Client* c, uint32_t peer_id, uint8_t* wrapping_key,
                          RoomSession* room)
{
    if (!c || !wrapping_key || !room)
    {
        return -1;
    }

    uint8_t buf[PKT_ENC_ROOM_KEY_PAYLOAD_LEN];

    uint8_t* p   = buf;
    size_t   off = 0;
    // [4 to_client_id]
    put_u32_be(p + off, peer_id);
    off += sizeof(peer_id);

    // [8 epoch]
    put_u64_be(p + off, room->epoch);
    off += sizeof(room->epoch);

    // [16 nonce]
    uint8_t* nonce_p = p + off;
    off += PKT_ENC_ROOM_KEY_NONCE_LEN;

    // [16 tag]
    uint8_t* tag_p = p + off;
    off += PKT_ENC_ROOM_KEY_TAG_LEN;

    // [32 encrypted_room_key]
    uint8_t* cipher_p = p + off;
    off += PKT_ENC_ROOM_KEY_CIPHERTEXT_LEN;

    Header h     = {0};
    h.flags      = 0;
    h.message_id = 0;
    h.room_id    = room->room_id;
    h.sender_id  = c->id;
    h.type       = PKT_ENC_ROOM_KEY;
    h.version    = 1;
    h.timestamp  = (uint64_t)time(NULL);

    if (e2e_wrap_room_key(c->id, peer_id, room->room_id, room->epoch, room->enc_key, room->room_key,
                          cipher_p, tag_p, nonce_p) < 0)
    {
        fprintf(stderr, "e2e_wrap_room_key failed\n");
        return -1;
    }

    if (enqueue_packet(c, &h, buf, sizeof(buf)) < 0)
    {
        fprintf(stderr, "enqueue_packet failed\n");
        return -1;
    }
    if (set_epollout_to_client(epfd, c) < 0)
    {
        fprintf(stderr, "set_epollout_to_client failed\n");
        return -1;
    }
    return 0;
}

// [2 identity_pub_der_len]
// [identity_pub_der]
// [2 signature_len]
// [signature]
int client_send_register_commit(int epfd, Client* c, uint8_t* identity_pub_der,
                                uint16_t identity_pub_der_len, uint8_t* sig, uint16_t siglen)
{
    int    ret   = -1;
    Header h     = {0};
    h.flags      = 0;
    h.message_id = 0;
    h.room_id    = c->room_id;
    h.sender_id  = c->id;
    h.timestamp  = (uint64_t)time(NULL);
    h.type       = PKT_REGISTER_RESPONSE;
    h.version    = 1;

    uint32_t out_buf_len = 2 + identity_pub_der_len + 2 + siglen;
    uint8_t* out_buf     = OPENSSL_malloc(out_buf_len);
    if (!out_buf)
    {
        ossl_print_error("OPENSSL_malloc");
        return -1;
    }
    uint8_t* p   = out_buf;
    size_t   off = 0;

    put_u16_be(p + off, identity_pub_der_len);
    off += 2;
    memcpy(p + off, identity_pub_der, identity_pub_der_len);
    off += identity_pub_der_len;
    put_u16_be(p + off, siglen);
    off += 2;
    memcpy(p + off, sig, siglen);

    if (enqueue_packet(c, &h, out_buf, out_buf_len) < 0)
    {
        fprintf(stderr, "enqueue_packet");
        goto cleanup;
    }
    if (set_epollout_to_client(epfd, c) < 0)
    {
        fprintf(stderr, "enqueue_packet");
        goto cleanup;
    }
    ret = 0;
cleanup:
    OPENSSL_free(out_buf);
    return ret;
}