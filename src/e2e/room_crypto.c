#include "e2e/room_crypto.h"

#include "crypto/crypto_core.h"
#include "e2e/e2e_protocol.h"
#include "e2e/room_password_packet.h"
#include "protocol/wire.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>

// 1. Из wrapping_key вывести два ключа:
//    enc_key
//    mac_key

// 2. Зашифровать room_key:
//    encrypted_room_key = Kuznyechik-CTR(enc_key, nonce, room_key)

// 3. Посчитать MAC:
//    tag = Kuznyechik-MAC(mac_key,
//        aad || nonce || encrypted_room_key
//    )

// AAD:
//     packet_type = PKT_ENC_ROOM_KEY
//     sender_id
//     to_client_id
//     room_id
//     epoch

// PLAINTEXT:
//     room_key

// OUTPUT:
//     encrypted_room_key
//     tag
int kuznechik_encrypt_room_key(uint8_t* nonce, uint8_t* enc_key, uint8_t* room_key,
                               int room_key_len, uint8_t* mac_key, uint8_t* aad, uint16_t aad_len,
                               uint8_t** out, uint16_t* out_len, uint8_t** tag_out,
                               uint16_t* tag_out_len)
{
    if (!nonce || !enc_key || !room_key || !mac_key || room_key_len != 32)
    {
        return -1;
    }

    int             ret                    = -1;
    EVP_CIPHER*     cipher                 = NULL;
    EVP_CIPHER_CTX* ctx                    = NULL;
    uint8_t*        encrypted_room_key     = NULL;
    int             encrypted_room_key_len = 0;
    int             outl                   = 0;
    EVP_MAC*        mac                    = NULL;
    EVP_MAC_CTX*    mctx                   = NULL;
    uint8_t*        tag                    = NULL;

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
    encrypted_room_key = OPENSSL_malloc(32);
    if (!encrypted_room_key)
    {
        ossl_print_error("encrypted_room_key");
        goto cleanup;
    }
    if (EVP_EncryptUpdate(ctx, encrypted_room_key, &outl, room_key, room_key_len) != 1)
    {
        ossl_print_error("EVP_EncryptUpdate");
        goto cleanup;
    }
    encrypted_room_key_len += outl;
    if (EVP_EncryptFinal_ex(ctx, encrypted_room_key + encrypted_room_key_len, &outl) != 1)
    {
        ossl_print_error("EVP_EncryptFinal_ex");
        goto cleanup;
    }
    encrypted_room_key_len += outl;

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

    if (EVP_MAC_update(mctx, aad, aad_len) != 1)
    {
        ossl_print_error("EVP_MAC_update");
        goto cleanup;
    }
    if (EVP_MAC_update(mctx, nonce, PKT_ENC_ROOM_KEY_NONCE_LEN) != 1)
    {
        ossl_print_error("EVP_MAC_update");
        goto cleanup;
    }
    if (EVP_MAC_update(mctx, encrypted_room_key, encrypted_room_key_len) != 1)
    {
        ossl_print_error("EVP_MAC_update");
        goto cleanup;
    }

    tag = OPENSSL_malloc(PKT_ENC_ROOM_KEY_TAG_LEN);
    if (!tag)
    {
        ossl_print_error("OPENSSL_malloc");
        goto cleanup;
    }
    size_t mac_len  = 0;
    size_t mac_outl = 0;
    if (EVP_MAC_final(mctx, tag, &mac_outl, PKT_ENC_ROOM_KEY_TAG_LEN) != 1)
    {
        ossl_print_error("EVP_MAC_final");
        goto cleanup;
    }
    mac_len += mac_outl;
    if (mac_len != PKT_ENC_ROOM_KEY_TAG_LEN)
    {
        fprintf(stderr, "invalid mac_len: %zu\n", mac_len);
        goto cleanup;
    }

    *out = encrypted_room_key;
    if (out_len)
    {
        *out_len = encrypted_room_key_len;
    }
    encrypted_room_key = NULL;
    *tag_out           = tag;
    tag                = NULL;

    if (tag_out_len)
    {
        *tag_out_len = (uint16_t)mac_len;
    }

    ret = 0;
cleanup:
    OPENSSL_free(encrypted_room_key);
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

int kuznechik_decrypt_room_key(uint8_t* nonce, uint8_t* enc_key, uint8_t* encrypted_room_key,
                               int encrypted_room_key_len, uint8_t* mac_key, uint8_t* aad,
                               uint16_t aad_len, uint8_t** out, uint16_t* out_len, uint8_t* tag_in,
                               uint16_t tag_in_len)
{
    if (!nonce || !enc_key || !encrypted_room_key || !mac_key || encrypted_room_key_len != 32 ||
        !out || !tag_in || !out_len)
    {
        return -1;
    }

    int             ret                    = -1;
    EVP_CIPHER*     cipher                 = NULL;
    EVP_CIPHER_CTX* ctx                    = NULL;
    uint8_t*        decrypted_room_key     = NULL;
    int             decrypted_room_key_len = 0;
    int             outl                   = 0;
    EVP_MAC*        mac                    = NULL;
    EVP_MAC_CTX*    mctx                   = NULL;
    uint8_t*        tag                    = NULL;

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

    if (EVP_MAC_update(mctx, aad, aad_len) != 1)
    {
        ossl_print_error("EVP_MAC_update");
        goto cleanup;
    }
    if (EVP_MAC_update(mctx, nonce, PKT_ENC_ROOM_KEY_NONCE_LEN) != 1)
    {
        ossl_print_error("EVP_MAC_update");
        goto cleanup;
    }
    if (EVP_MAC_update(mctx, encrypted_room_key, encrypted_room_key_len) != 1)
    {
        ossl_print_error("EVP_MAC_update");
        goto cleanup;
    }

    tag = OPENSSL_malloc(PKT_ENC_ROOM_KEY_TAG_LEN);
    if (!tag)
    {
        ossl_print_error("OPENSSL_malloc");
        goto cleanup;
    }
    size_t mac_len  = 0;
    size_t mac_outl = 0;
    if (EVP_MAC_final(mctx, tag, &mac_outl, PKT_ENC_ROOM_KEY_TAG_LEN) != 1)
    {
        ossl_print_error("EVP_MAC_final");
        goto cleanup;
    }
    mac_len += mac_outl;
    if (mac_len != PKT_ENC_ROOM_KEY_TAG_LEN || tag_in_len != PKT_ENC_ROOM_KEY_TAG_LEN)
    {
        fprintf(stderr, "invalid mac_len: %zu\n", mac_len);
        goto cleanup;
    }
    if (CRYPTO_memcmp(tag, tag_in, tag_in_len) != 0)
    {
        fprintf(stderr, "invalid tag\n");
        ret = -2;
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
        ossl_print_error("EVP_EncryptInit_ex2");
        goto cleanup;
    }
    decrypted_room_key = OPENSSL_malloc(32);
    if (!decrypted_room_key)
    {
        ossl_print_error("encrypted_room_key");
        goto cleanup;
    }
    if (EVP_DecryptUpdate(ctx, decrypted_room_key, &outl, encrypted_room_key,
                          encrypted_room_key_len) != 1)
    {
        ossl_print_error("EVP_EncryptUpdate");
        goto cleanup;
    }
    decrypted_room_key_len += outl;
    if (EVP_DecryptFinal_ex(ctx, decrypted_room_key + decrypted_room_key_len, &outl) != 1)
    {
        ossl_print_error("EVP_EncryptFinal_ex");
        goto cleanup;
    }
    decrypted_room_key_len += outl;
    if (decrypted_room_key_len != ROOM_KEY_LEN)
    {
        fprintf(stderr, "decrypted_room_key_len mismatch\n");
        goto cleanup;
    }

    *out = decrypted_room_key;
    if (out_len)
    {
        *out_len = decrypted_room_key_len;
    }
    decrypted_room_key = NULL;

    ret = 0;
cleanup:
    OPENSSL_clear_free(decrypted_room_key, ROOM_KEY_LEN);
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

int save_peer_wrap_session(PeerWrapSession* peers, size_t count, uint32_t peer_id,
                           uint8_t* fingerprint, uint16_t fingerprint_len, uint8_t* wrapping_key)
{
    PeerWrapSession* slot = NULL;
    for (size_t i = 0; i < count; i++)
    {
        if (peers[i].used && peers[i].peer_id == peer_id)
        {
            if (peers[i].fingerprint_len != fingerprint_len ||
                memcmp(peers[i].fingerprint, fingerprint, fingerprint_len) != 0)
            {
                fprintf(stderr, "[E2E] fingerprint changed for peer #%" PRIu32 "\n", peer_id);
                return -1;
            }
            slot = &peers[i];
            break;
        }
    }

    if (!slot)
    {
        for (size_t i = 0; i < count; i++)
        {
            if (!peers[i].used)
            {
                slot = &peers[i];
            }
        }
    }
    if (!slot)
    {
        fprintf(stderr, "peer wrap table is full\n");
        return -1;
    }

    OPENSSL_cleanse(slot, sizeof(*slot));

    slot->peer_id = peer_id;
    if (fingerprint_len > sizeof(peers[0].fingerprint))
    {
        fprintf(stderr, "fingerprint too long\n");
        return -1;
    }
    memcpy(slot->fingerprint, fingerprint, fingerprint_len);
    slot->fingerprint_len = fingerprint_len;
    memcpy(slot->wrapping_key, wrapping_key, WRAPPING_KEY_LEN);
    slot->used = 1;

    return 0;
}

int get_password_key(uint8_t* password, uint16_t password_len, uint8_t salt[ROOM_SALT_LEN],
                     uint8_t out_key[PASSWORD_KEY_LEN], uint8_t* info, uint16_t info_len)
{
    if (get_kdf(password, password_len, salt, ROOM_SALT_LEN, info, info_len, out_key,
                PASSWORD_KEY_LEN) < 0)
    {
        return -1;
    }
    return 0;
}

int generate_new_rpi(RoomPasswordInfo* rpi)
{
    if (RAND_bytes(rpi->nonce, ROOM_NONCE_LEN) != 1)
    {
        return -1;
    }
    if (RAND_bytes(rpi->salt, ROOM_SALT_LEN) != 1)
    {
        return -1;
    }

    return 0;
}

int generate_room_key(uint8_t room_key[ROOM_KEY_LEN])
{
    if (RAND_bytes(room_key, ROOM_KEY_LEN) != 1)
    {
        return -1;
    }
    return 0;
}

int encrypt_room_key_with_password(uint32_t room_id, uint8_t* password, uint16_t password_len,
                                   uint8_t plaintext_room_key[ROOM_KEY_LEN], RoomPasswordInfo* rpi)
{
    char info_enc[50];
    snprintf(info_enc, sizeof(info_enc), "room_password_enc_key%" PRIu32 "", room_id);
    char info_mac[50] = "room_password_mac_key";
    snprintf(info_mac, sizeof(info_enc), "room_password_mac_key%" PRIu32 "", room_id);
    uint8_t enc_key[PASSWORD_KEY_LEN];
    uint8_t mac_key[PASSWORD_KEY_LEN];
    if (get_password_key(password, password_len, rpi->salt, enc_key, (uint8_t*)info_enc,
                         (uint16_t)(strlen(info_enc))) < 0)
    {
        fprintf(stderr, "get_password_key failed\n");
        return -1;
    }
    if (get_password_key(password, password_len, rpi->salt, mac_key, (uint8_t*)info_mac,
                         (uint16_t)(strlen(info_mac))) < 0)
    {
        fprintf(stderr, "get_password_key failed\n");
        return -1;
    }

    uint8_t aad_label[22] = "room-password-wrap-v1";
    uint8_t aad[sizeof(aad_label) - 1 + ROOM_ID_LEN];
    size_t  off = 0;
    memset(aad, 0, sizeof(aad));
    memcpy(aad, aad_label, sizeof(aad_label) - 1);
    off += sizeof(aad_label) - 1;
    put_u32_be(aad + off, room_id);
    off += ROOM_ID_LEN;

    uint8_t* key_local;
    uint16_t key_local_len;
    uint8_t* tag_local;
    uint16_t tag_local_len;
    int      ret = kuznechik_encrypt_room_key(rpi->nonce, enc_key, plaintext_room_key, ROOM_KEY_LEN,
                                              mac_key, aad, sizeof(aad), &key_local, &key_local_len,
                                              &tag_local, &tag_local_len);
    if (ret < 0)
    {
        fprintf(stderr, "kuznechik_decrypt_room_key failed\n");
        return -1;
    }

    memcpy(rpi->encrypted_room_key, key_local, key_local_len);
    memcpy(rpi->tag, tag_local, tag_local_len);

    if (get_verifier(mac_key, room_id, rpi->epoch, rpi->verifier) < 0)
    {
        fprintf(stderr, "get_verifier failed\n");
        return -1;
    }

    OPENSSL_free(key_local);
    OPENSSL_free(tag_local);
    return 0;
}

int try_decrypt_room_key(uint32_t room_id, uint8_t* password, uint16_t password_len,
                         RoomPasswordInfo* rpi, uint8_t out_room_key[ROOM_KEY_LEN])
{
    char info_enc[50];
    snprintf(info_enc, sizeof(info_enc), "room_password_enc_key%" PRIu32 "", room_id);
    char info_mac[50] = "room_password_mac_key";
    snprintf(info_mac, sizeof(info_enc), "room_password_mac_key%" PRIu32 "", room_id);
    uint8_t enc_key[PASSWORD_KEY_LEN];
    uint8_t mac_key[PASSWORD_KEY_LEN];
    if (get_password_key(password, password_len, rpi->salt, enc_key, (uint8_t*)info_enc,
                         (uint16_t)(strlen(info_enc))) < 0)
    {
        fprintf(stderr, "get_password_key failed\n");
        return -1;
    }
    if (get_password_key(password, password_len, rpi->salt, mac_key, (uint8_t*)info_mac,
                         (uint16_t)(strlen(info_mac))) < 0)
    {
        fprintf(stderr, "get_password_key failed\n");
        return -1;
    }

    uint8_t aad_label[22] = "room-password-wrap-v1";
    uint8_t aad[sizeof(aad_label) - 1 + ROOM_ID_LEN];
    size_t  off = 0;
    memset(aad, 0, sizeof(aad));
    memcpy(aad + off, aad_label, sizeof(aad_label) - 1);
    off += sizeof(aad_label) - 1;
    put_u32_be(aad + off, room_id);
    off += ROOM_ID_LEN;

    uint8_t* local_out;
    uint16_t local_out_len;
    int      ret = kuznechik_decrypt_room_key(rpi->nonce, enc_key, rpi->encrypted_room_key,
                                              ENCRYPTED_ROOM_KEY_LEN, mac_key, aad, sizeof(aad),
                                              &local_out, &local_out_len, rpi->tag, ROOM_TAG_LEN);
    if (ret == -2)
    {
        return -2;
    }
    else if (ret < 0)
    {
        fprintf(stderr, "kuznechik_decrypt_room_key failed\n");
        return -1;
    }
    memcpy(out_room_key, local_out, local_out_len);
    OPENSSL_clear_free(local_out, local_out_len);
    return 0;
}

int try_decrypt_room_key_ex(uint32_t room_id, uint8_t* password, uint16_t password_len,
                            RoomPasswordInfo* rpi, uint8_t out_room_key[ROOM_KEY_LEN],
                            uint8_t out_enc_key[PASSWORD_KEY_LEN],
                            uint8_t out_mac_key[ROOM_PASS_KEY_LEN])
{
    char info_enc[50];
    snprintf(info_enc, sizeof(info_enc), "room_password_enc_key%" PRIu32 "", room_id);
    char info_mac[50] = "room_password_mac_key";
    snprintf(info_mac, sizeof(info_enc), "room_password_mac_key%" PRIu32 "", room_id);
    uint8_t enc_key[PASSWORD_KEY_LEN];
    uint8_t mac_key[PASSWORD_KEY_LEN];
    if (get_password_key(password, password_len, rpi->salt, enc_key, (uint8_t*)info_enc,
                         (uint16_t)(strlen(info_enc))) < 0)
    {
        fprintf(stderr, "get_password_key failed\n");
        return -1;
    }
    if (get_password_key(password, password_len, rpi->salt, mac_key, (uint8_t*)info_mac,
                         (uint16_t)(strlen(info_mac))) < 0)
    {
        fprintf(stderr, "get_password_key failed\n");
        return -1;
    }

    uint8_t aad_label[22] = "room-password-wrap-v1";
    uint8_t aad[sizeof(aad_label) - 1 + ROOM_ID_LEN];
    size_t  off = 0;
    memset(aad, 0, sizeof(aad));
    memcpy(aad + off, aad_label, sizeof(aad_label) - 1);
    off += sizeof(aad_label) - 1;
    put_u32_be(aad + off, room_id);
    off += ROOM_ID_LEN;

    uint8_t* local_out;
    uint16_t local_out_len;
    int      ret = kuznechik_decrypt_room_key(rpi->nonce, enc_key, rpi->encrypted_room_key,
                                              ENCRYPTED_ROOM_KEY_LEN, mac_key, aad, sizeof(aad),
                                              &local_out, &local_out_len, rpi->tag, ROOM_TAG_LEN);
    if (ret == -2)
    {
        return -2;
    }
    else if (ret < 0)
    {
        fprintf(stderr, "kuznechik_decrypt_room_key failed\n");
        return -1;
    }
    memcpy(out_room_key, local_out, local_out_len);
    memcpy(out_enc_key, enc_key, PASSWORD_KEY_LEN);
    memcpy(out_mac_key, mac_key, PASSWORD_KEY_LEN);
    OPENSSL_clear_free(local_out, local_out_len);
    return 0;
}

int encrypt_room_key_with_password_keys(uint32_t room_id, uint8_t enc_key[PASSWORD_KEY_LEN],
                                        uint8_t           mac_key[PASSWORD_KEY_LEN],
                                        uint8_t           plaintext_room_key[ROOM_KEY_LEN],
                                        RoomPasswordInfo* rpi)
{
    char info_enc[50];
    snprintf(info_enc, sizeof(info_enc), "room_password_enc_key%" PRIu32 "", room_id);
    char info_mac[50] = "room_password_mac_key";
    snprintf(info_mac, sizeof(info_enc), "room_password_mac_key%" PRIu32 "", room_id);

    uint8_t aad_label[22] = "room-password-wrap-v1";
    uint8_t aad[sizeof(aad_label) - 1 + ROOM_ID_LEN];
    size_t  off = 0;
    memset(aad, 0, sizeof(aad));
    memcpy(aad, aad_label, sizeof(aad_label) - 1);
    off += sizeof(aad_label) - 1;
    put_u32_be(aad + off, room_id);
    off += ROOM_ID_LEN;

    uint8_t* key_local;
    uint16_t key_local_len;
    uint8_t* tag_local;
    uint16_t tag_local_len;
    int      ret = kuznechik_encrypt_room_key(rpi->nonce, enc_key, plaintext_room_key, ROOM_KEY_LEN,
                                              mac_key, aad, sizeof(aad), &key_local, &key_local_len,
                                              &tag_local, &tag_local_len);
    if (ret < 0)
    {
        fprintf(stderr, "kuznechik_decrypt_room_key failed\n");
        return -1;
    }
    memcpy(rpi->encrypted_room_key, key_local, key_local_len);
    memcpy(rpi->tag, tag_local, tag_local_len);
    OPENSSL_free(key_local);
    OPENSSL_free(tag_local);
    return 0;
}

// HMAC(
//     key = mac_key,
//     data = "room_password_server_v1" || room_id || epoch,
//     out = verifier
// )
int get_verifier(uint8_t mac_key[ROOM_KEY_LEN], uint32_t room_id, uint64_t epoch,
                 uint8_t out_verifier[ROOM_PASSWORD_VERIFIER_LEN])
{
    int          ret = -1;
    EVP_MAC*     mac = NULL;
    EVP_MAC_CTX* ctx;
    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac)
    {
        ossl_print_error("EVP_MAC_fetch");
        goto cleanup;
    }
    ctx = EVP_MAC_CTX_new(mac);
    if (!ctx)
    {
        ossl_print_error("EVP_MAC_CTX_new");
        goto cleanup;
    }
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "md_gost12_256", 0),
        OSSL_PARAM_construct_end()};
    if (EVP_MAC_init(ctx, mac_key, ROOM_KEY_LEN, params) != 1)
    {
        ossl_print_error("EVP_MAC_init");
        goto cleanup;
    }
    char line[] = "room_password_server_v1";
    if (EVP_MAC_update(ctx, (uint8_t*)line, strlen(line)) != 1)
    {
        ossl_print_error("EVP_MAC_update");
        goto cleanup;
    }

    uint8_t room_id_be[ROOM_ID_LEN] = {0};
    put_u32_be(room_id_be, room_id);

    if (EVP_MAC_update(ctx, room_id_be, ROOM_ID_LEN) != 1)
    {
        ossl_print_error("EVP_MAC_update");
        goto cleanup;
    }

    uint8_t epoch_be[EPOCH_LEN] = {0};
    put_u64_be(epoch_be, epoch);

    if (EVP_MAC_update(ctx, epoch_be, EPOCH_LEN) != 1)
    {
        ossl_print_error("EVP_MAC_update");
        goto cleanup;
    }

    size_t outl;
    if (EVP_MAC_final(ctx, out_verifier, &outl, ROOM_PASSWORD_VERIFIER_LEN) != 1)
    {
        ossl_print_error("EVP_MAC_final");
        goto cleanup;
    }
    if (outl != ROOM_PASS_KEY_LEN)
    {
        fprintf(stderr, "outl and ROOM_PASS_KEY_LEN differ\n");
        goto cleanup;
    }

    ret = 0;
cleanup:
    EVP_MAC_free(mac);
    EVP_MAC_CTX_free(ctx);
    return ret;
}