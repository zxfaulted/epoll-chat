#include "e2e_message.h"
#include "crypto.h"
#include "e2e_protocol.h"
#include "protocol.h"
#include "wire.h"
#include <openssl/evp.h>
#include <stddef.h>

// [1 packet_type]
// [1 enc_version]
// [1 suite]
// [2 reserved]
// [4 sender_id]
// [4 room_id]
// [8 room_epoch]
// [8 seq]
static int build_aad_for_enc_chat(uint8_t  aad_for_enc_chat[AAD_FOR_ENC_CHAT_LEN],
                                  uint32_t sender_id, uint32_t room_id, uint64_t epoch,
                                  uint64_t seq)
{
    if (!aad_for_enc_chat)
    {
        return -1;
    }
    size_t   off = 0;
    uint8_t* p   = aad_for_enc_chat;

    // [1 packet_type]
    *(p + off) = PKT_ENC_CHAT;
    off++;

    // [1 enc_version]
    *(p + off) = 1;
    off++;

    // [1 suite]
    *(p + off) = 1;
    off++;

    // [2 reserved]
    *(p + off) = 0;
    off++;
    *(p + off) = 0;
    off++;

    // [4 sender_id]
    put_u32_be(p + off, sender_id);
    off += sizeof(sender_id);

    // [4 room_id]
    put_u32_be(p + off, room_id);
    off += sizeof(room_id);

    // [8 room_epoch]
    put_u64_be(p + off, epoch);
    off += sizeof(epoch);

    // [8 seq]
    put_u64_be(p + off, seq);
    off += sizeof(seq);

    if (off != AAD_FOR_ENC_CHAT_LEN)
    {
        return -1;
    }
    return 0;
}

int kuznechik_encrypt_message(uint8_t* nonce, uint8_t* enc_key, uint8_t* msg, int msg_len,
                              uint8_t* mac_key, uint8_t aad[AAD_FOR_ENC_CHAT_LEN], uint8_t** out,
                              uint16_t* out_len, uint8_t** tag_out, uint16_t* tag_out_len)
{
    if (!nonce || !enc_key || !msg || msg_len < 0 || msg_len > ENC_PLAINTEXT_MAX_LEN || !mac_key ||
        !tag_out || !out || !aad)
    {
        return -1;
    }

    int             ret         = -1;
    EVP_CIPHER*     cipher      = NULL;
    EVP_CIPHER_CTX* ctx         = NULL;
    uint8_t*        enc_msg     = NULL;
    int             enc_msg_len = 0;
    int             outl        = 0;
    EVP_MAC*        mac         = NULL;
    EVP_MAC_CTX*    mctx        = NULL;
    uint8_t*        tag         = NULL;

    cipher = EVP_CIPHER_fetch(NULL, "kuznyechik-ctr-acpkm", NULL);
    if (!cipher)
    {
        ossl_print_error("EVP_CIPHER_fetch");
        goto cleanup;
    }
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        ossl_print_error("EVP_CIPHER_CTX_new");
        goto cleanup;
    }
    if (EVP_EncryptInit_ex2(ctx, cipher, enc_key, nonce, NULL) != 1)
    {
        ossl_print_error("EVP_EncryptInit_ex2");
        goto cleanup;
    }
    enc_msg = OPENSSL_malloc(msg_len > 0 ? msg_len : 1);
    if (!enc_msg)
    {
        ossl_print_error("encrypted_room_key");
        goto cleanup;
    }
    if (EVP_EncryptUpdate(ctx, enc_msg, &outl, msg, msg_len) != 1)
    {
        ossl_print_error("EVP_EncryptUpdate");
        goto cleanup;
    }
    enc_msg_len += outl;
    if (EVP_EncryptFinal_ex(ctx, enc_msg + enc_msg_len, &outl) != 1)
    {
        ossl_print_error("EVP_EncryptFinal_ex");
        goto cleanup;
    }
    enc_msg_len += outl;

    mac = EVP_MAC_fetch(NULL, "kuznyechik-mac", NULL);
    if (!mac)
    {
        ossl_print_error("EVP_MAC_fetch");
        goto cleanup;
    }
    mctx = EVP_MAC_CTX_new(mac);
    if (!mctx)
    {
        ossl_print_error("EVP_MAC_CTX_new");
        goto cleanup;
    }
    if (EVP_MAC_init(mctx, mac_key, 32, NULL) != 1)
    {
        ossl_print_error("EVP_MAC_init");
        goto cleanup;
    }

    if (EVP_MAC_update(mctx, aad, AAD_FOR_ENC_CHAT_LEN) != 1)
    {
        ossl_print_error("EVP_MAC_update");
        goto cleanup;
    }
    if (EVP_MAC_update(mctx, nonce, ENC_NONCE) != 1)
    {
        ossl_print_error("EVP_MAC_update");
        goto cleanup;
    }
    if (EVP_MAC_update(mctx, enc_msg, enc_msg_len) != 1)
    {
        ossl_print_error("EVP_MAC_update");
        goto cleanup;
    }

    tag = OPENSSL_malloc(ENC_TAG);
    if (!tag)
    {
        ossl_print_error("OPENSSL_malloc");
        goto cleanup;
    }
    size_t mac_len  = 0;
    size_t mac_outl = 0;
    if (EVP_MAC_final(mctx, tag, &mac_outl, ENC_TAG) != 1)
    {
        ossl_print_error("EVP_MAC_final");
        goto cleanup;
    }
    mac_len += mac_outl;
    if (mac_len != ENC_TAG)
    {
        fprintf(stderr, "invalid mac_len: %zu\n", mac_len);
        goto cleanup;
    }

    if (enc_msg_len > UINT16_MAX)
    {
        fprintf(stderr, "enc_msg_len too large\n");
        goto cleanup;
    }
    *out = enc_msg;
    if (out_len)
    {
        *out_len = (uint16_t)enc_msg_len;
    }
    enc_msg  = NULL;
    *tag_out = tag;
    tag      = NULL;

    if (tag_out_len)
    {
        *tag_out_len = (uint16_t)mac_len;
    }

    ret = 0;
cleanup:
    OPENSSL_free(enc_msg);
    OPENSSL_free(tag);
    EVP_CIPHER_free(cipher);
    cipher = NULL;
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;
    EVP_MAC_CTX_free(mctx);
    mctx = NULL;
    EVP_MAC_free(mac);
    mac = NULL;

    return ret;
}

int kuznechik_decrypt_message(uint8_t* nonce, uint8_t* enc_key, uint8_t* msg, int msg_len,
                              uint8_t* mac_key, uint8_t aad[AAD_FOR_ENC_CHAT_LEN], uint8_t** out,
                              uint16_t* out_len, uint8_t* tag_in, uint16_t tag_in_len)
{
    if (!nonce || !enc_key || !msg || !mac_key || msg_len < 0 || msg_len > ENC_PLAINTEXT_MAX_LEN ||
        !out || !tag_in || !out_len)
    {
        return -1;
    }

    int             ret               = -1;
    EVP_CIPHER*     cipher            = NULL;
    EVP_CIPHER_CTX* ctx               = NULL;
    uint8_t*        decrypted_msg     = NULL;
    int             decrypted_msg_len = 0;
    int             outl              = 0;
    EVP_MAC*        mac               = NULL;
    EVP_MAC_CTX*    mctx              = NULL;
    uint8_t*        tag               = NULL;

    mac = EVP_MAC_fetch(NULL, "kuznyechik-mac", NULL);
    if (!mac)
    {
        ossl_print_error("EVP_MAC_fetch");
        goto cleanup;
    }
    mctx = EVP_MAC_CTX_new(mac);
    if (!mctx)
    {
        ossl_print_error("EVP_MAC_CTX_new");
        goto cleanup;
    }
    if (EVP_MAC_init(mctx, mac_key, 32, NULL) != 1)
    {
        ossl_print_error("EVP_MAC_init");
        goto cleanup;
    }

    if (EVP_MAC_update(mctx, aad, AAD_FOR_ENC_CHAT_LEN) != 1)
    {
        ossl_print_error("EVP_MAC_update");
        goto cleanup;
    }
    if (EVP_MAC_update(mctx, nonce, ENC_NONCE) != 1)
    {
        ossl_print_error("EVP_MAC_update");
        goto cleanup;
    }
    if (EVP_MAC_update(mctx, msg, msg_len) != 1)
    {
        ossl_print_error("EVP_MAC_update");
        goto cleanup;
    }

    tag = OPENSSL_malloc(ENC_TAG);
    if (!tag)
    {
        ossl_print_error("OPENSSL_malloc");
        goto cleanup;
    }
    size_t mac_len  = 0;
    size_t mac_outl = 0;
    if (EVP_MAC_final(mctx, tag, &mac_outl, ENC_TAG) != 1)
    {
        ossl_print_error("EVP_MAC_final");
        goto cleanup;
    }
    mac_len += mac_outl;
    if (mac_len != ENC_TAG || tag_in_len != ENC_TAG)
    {
        fprintf(stderr, "invalid mac_len: %zu\n", mac_len);
        goto cleanup;
    }
    if (CRYPTO_memcmp(tag, tag_in, tag_in_len) != 0)
    {
        fprintf(stderr, "invalid tag\n");
        goto cleanup;
    }

    cipher = EVP_CIPHER_fetch(NULL, "kuznyechik-ctr-acpkm", NULL);
    if (!cipher)
    {
        ossl_print_error("EVP_CIPHER_fetch");
        goto cleanup;
    }
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        ossl_print_error("EVP_CIPHER_CTX_new");
        goto cleanup;
    }
    if (EVP_DecryptInit_ex2(ctx, cipher, enc_key, nonce, NULL) != 1)
    {
        ossl_print_error("EVP_DecryptInit_ex2");
        goto cleanup;
    }
    decrypted_msg = OPENSSL_malloc(msg_len > 0 ? msg_len : 1);
    if (!decrypted_msg)
    {
        ossl_print_error("OPENSSL_malloc");
        goto cleanup;
    }
    if (EVP_DecryptUpdate(ctx, decrypted_msg, &outl, msg, msg_len) != 1)
    {
        ossl_print_error("EVP_DecryptUpdate");
        goto cleanup;
    }
    decrypted_msg_len += outl;
    if (EVP_DecryptFinal_ex(ctx, decrypted_msg + decrypted_msg_len, &outl) != 1)
    {
        ossl_print_error("EVP_DecryptFinal_ex");
        goto cleanup;
    }
    decrypted_msg_len += outl;
    if (decrypted_msg_len > ENC_PLAINTEXT_MAX_LEN)
    {
        fprintf(stderr, "decrypted_msg_len too large\n");
        goto cleanup;
    }
    *out = decrypted_msg;
    if (out_len)
    {
        *out_len = (uint16_t)decrypted_msg_len;
    }
    decrypted_msg = NULL;

    ret = 0;
cleanup:
    OPENSSL_clear_free(decrypted_msg, msg_len > 0 ? msg_len : 1);
    OPENSSL_free(tag);
    EVP_CIPHER_free(cipher);
    cipher = NULL;
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;
    EVP_MAC_CTX_free(mctx);
    mctx = NULL;
    EVP_MAC_free(mac);
    mac = NULL;

    return ret;
}

int encrypt_chat_message(uint8_t room_key[ROOM_KEY_LEN], uint32_t sender_id, uint32_t room_id,
                         uint64_t epoch, uint64_t send_seq, uint8_t* msg, uint16_t msg_len,
                         uint8_t** out_msg, uint16_t* out_msg_len, uint8_t** out_tag,
                         uint16_t* out_tag_len, uint8_t** out_nonce)
{
    if (!room_key || !msg || !out_msg || !out_tag || !out_msg_len || !out_tag_len || !out_nonce)
    {
        return -1;
    }

    uint8_t* cipher     = NULL;
    uint16_t cipher_len = 0;
    uint8_t* tag        = NULL;
    uint16_t tag_len    = 0;
    size_t   off        = 0;
    int      ret        = -1;
    // sender_id: 4 байта
    // seq:       8 байт
    // random32:  4 байта
    uint8_t* nonce = OPENSSL_malloc(ENC_NONCE);
    if (!nonce)
    {
        ossl_print_error("OPENSSL_malloc");
        goto cleanup;
    }
    // sender_id: 4 байта
    put_u32_be(nonce + off, sender_id);
    off += sizeof(sender_id);
    // seq:       8 байт
    put_u64_be(nonce + off, send_seq);
    off += sizeof(send_seq);
    // random32:  4 байта
    if (RAND_bytes(nonce + off, 4) != 1)
    {
        ossl_print_error("RAND_bytes");
        goto cleanup;
    }
    off += 4;
    if (off != ENC_NONCE)
    {
        fprintf(stderr, "NONCE len mismatch");
        goto cleanup;
    }

    uint8_t mac_key[32];
    uint8_t enc_key[32];

    uint8_t aad[AAD_FOR_ENC_CHAT_LEN];
    if (build_aad_for_enc_chat(aad, sender_id, room_id, epoch, send_seq))
    {
        fprintf(stderr, "build_aad_for_enc_chat failed\n");
        goto cleanup;
    }
    const unsigned char salt_enc[] = "enc-chat enc";
    if (get_kdf(room_key, ROOM_KEY_LEN, salt_enc, (uint16_t)(sizeof(salt_enc) - 1), aad,
                AAD_FOR_ENC_CHAT_LEN, enc_key, 32) < 0)
    {
        fprintf(stderr, "get_kdf failed\n");
        goto cleanup;
    }
    const unsigned char salt_mac[] = "enc-chat mac";
    if (get_kdf(room_key, ROOM_KEY_LEN, salt_mac, (uint16_t)(sizeof(salt_mac) - 1), aad,
                AAD_FOR_ENC_CHAT_LEN, mac_key, 32) < 0)
    {
        fprintf(stderr, "get_kdf failed\n");
        goto cleanup;
    }
    if (kuznechik_encrypt_message(nonce, enc_key, msg, msg_len, mac_key, aad, &cipher, &cipher_len,
                                  &tag, &tag_len) < 0 ||
        !cipher || !tag)
    {
        fprintf(stderr, "kuznechik_encrypt_message failed\n");
        goto cleanup;
    }
    if (cipher_len > ENC_PLAINTEXT_MAX_LEN)
    {
        fprintf(stderr, "cipher_len too large\n");
        goto cleanup;
    }
    if (tag_len != ENC_TAG)
    {
        fprintf(stderr, "cipher_len mismatch\n");
        goto cleanup;
    }

    *out_msg     = cipher;
    *out_msg_len = cipher_len;
    *out_tag     = tag;
    *out_tag_len = tag_len;
    *out_nonce   = nonce;
    cipher       = NULL;
    tag          = NULL;
    nonce        = NULL;
    ret          = 0;
cleanup:
    OPENSSL_free(nonce);
    OPENSSL_free(cipher);
    OPENSSL_free(tag);
    OPENSSL_cleanse(mac_key, sizeof mac_key);
    OPENSSL_cleanse(enc_key, sizeof enc_key);
    return ret;
}

int decrypt_chat_message(uint8_t* nonce, uint8_t room_key[ROOM_KEY_LEN], uint32_t sender_id,
                         uint32_t room_id, uint64_t epoch, uint64_t seq, uint8_t* msg,
                         uint16_t msg_len, uint8_t* tag, uint8_t** out_msg, uint16_t* out_msg_len)
{
    if (!nonce || !room_key || !msg || !out_msg || !out_msg_len || !tag)
    {
        return -1;
    }

    uint8_t* cipher     = NULL;
    uint16_t cipher_len = 0;
    int      ret        = -1;
    uint8_t  mac_key[32];
    uint8_t  enc_key[32];

    uint8_t aad[AAD_FOR_ENC_CHAT_LEN];
    if (build_aad_for_enc_chat(aad, sender_id, room_id, epoch, seq))
    {
        fprintf(stderr, "build_aad_for_enc_chat failed\n");
        goto cleanup;
    }
    const unsigned char salt_enc[] = "enc-chat enc";
    if (get_kdf(room_key, ROOM_KEY_LEN, salt_enc, (uint16_t)(sizeof(salt_enc) - 1), aad,
                AAD_FOR_ENC_CHAT_LEN, enc_key, 32) < 0)
    {
        fprintf(stderr, "get_kdf failed\n");
        goto cleanup;
    }
    const unsigned char salt_mac[] = "enc-chat mac";
    if (get_kdf(room_key, ROOM_KEY_LEN, salt_mac, (uint16_t)(sizeof(salt_mac) - 1), aad,
                AAD_FOR_ENC_CHAT_LEN, mac_key, 32) < 0)
    {
        fprintf(stderr, "get_kdf failed\n");
        goto cleanup;
    }
    if (kuznechik_decrypt_message(nonce, enc_key, msg, msg_len, mac_key, aad, &cipher, &cipher_len,
                                  tag, ENC_TAG) < 0 ||
        !cipher)
    {
        fprintf(stderr, "kuznechik_decrypt_message failed\n");
        goto cleanup;
    }
    if (cipher_len > ENC_PLAINTEXT_MAX_LEN)
    {
        fprintf(stderr, "cipher_len too large\n");
        goto cleanup;
    }

    *out_msg     = cipher;
    *out_msg_len = cipher_len;
    cipher       = NULL;
    ret          = 0;
cleanup:
    if (ret != 0)
    {
        *out_msg     = NULL;
        *out_msg_len = 0;
    }

    OPENSSL_free(cipher);
    OPENSSL_cleanse(mac_key, sizeof mac_key);
    OPENSSL_cleanse(enc_key, sizeof enc_key);
    return ret;
}